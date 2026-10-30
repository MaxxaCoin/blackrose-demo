"""DNS-rebinding fix, cleanup pass: replace the mangled fetchPublicUrl region
with the clean pinned version."""
import sys

P = r'C:\Users\pc\Desktop\BlackRose\cline\blackrose\src\tools\knowledge.ts'
c = open(P, 'rb').read().decode('utf-8').replace('\r\n', '\n')

START = "/**\n * Fetch an http(s) URL with the SSRF guard, shared by knowledge_ingest/**"
END = "/** SHA-256 of text (idempotency key; never stored for original content). */"
i = c.index(START)
j = c.index(END)

NEW = """/**
 * Fetch an http(s) URL with the SSRF guard, shared by knowledge_ingest
 * (loadIngestText) and learn_url. Follows redirects MANUALLY, re-validating
 * every hop: a public URL that 302s to http://127.0.0.1/ is the classic bypass
 * of a pre-flight check. Numeric / hex IPv4 forms (http://2130706433/ =
 * 127.0.0.1) and IPv6 literals never belong to a knowledge source.
 * learn_url used to plain-fetch with redirect-following - the exact bypass
 * this engine already refused one call away (2026-10-26 sweep H3).
 *
 * THE PIN (2026-10-26 release follow-up): the guard's dns.promises.lookup and
 * the socket's connect used to be two INDEPENDENT OS getaddrinfo queries, so
 * attacker DNS with TTL 0 answered public to the guard and private to the
 * connect - reproduced live with learn_url landing on a loopback server while
 * the guard saw a public IP. The guarded fetch below pins the connect to the
 * validated array via an http(s) `lookup` hook (fetch has no such hook -
 * undici #421 - and undici itself violates zero-dep), so validation and
 * connect consume the SAME answers. The URL keeps its hostname form, so TLS
 * SNI and the certificate check still see the real host.
 */

/** A `lookup` hook that answers ONLY from the validated address array. */
function pinnedLookup(addrs: { address: string; family: number }[]): NonNullable<net.LookupFunction> {
  return (
    _hostname: string,
    options: { all?: boolean; family?: number },
    callback: (err: Error | null, address?: unknown, family?: number) => void,
  ) => {
    const usable = addrs.filter((a) => (options?.family ? a.family === options.family : true))
    if (usable.length === 0) {
      process.nextTick(() =>
        callback(new Error('no validated address usable for this connection (pinned SSRF lookup)')))
      return
    }
    process.nextTick(() => {
      if (options?.all) {
        // all:true → callback(null, [{address, family}...])
        ;(callback as unknown as (e: Error | null, a: unknown) => void)(null, usable)
      } else {
        callback(null, usable[0]!.address, usable[0]!.family)
      }
    })
  }
}

async function guardedRequest(
  u: string,
  pinned: { address: string; family: number }[] | null,
): Promise<Response> {
  const parsed = new URL(u)
  const mod = parsed.protocol === 'https:' ? https : http
  return await new Promise<Response>((resolve, reject) => {
    // The URL stays the HOSTNAME form (SNI/certificate check still see the
    // real host); only the DNS answer is pinned. `lookup` reaches
    // net/tls.connect, which then never queries the resolver. pinned === null
    // (the owner's allowLoopbackFetch capability) resolves normally.
    const req = mod.request(
      parsed,
      {
        method: 'GET',
        headers: { 'user-agent': 'Mozilla/5.0 (BlackRose personal assistant)' },
        ...(pinned ? { lookup: pinnedLookup(pinned) } : {}),
      },
      (inc) => {
        clearTimeout(timer)
        const headers = new Headers()
        for (const [k, v] of Object.entries(inc.headers)) {
          if (Array.isArray(v)) v.forEach((vv) => headers.append(k, String(vv)))
          else if (typeof v === 'string') headers.set(k, v)
        }
        const body = Readable.toWeb(inc) as unknown as ReadableStream
        resolve(new Response(body, { status: inc.statusCode ?? 0, headers }))
      },
    )
    const timer = setTimeout(() => {
      req.destroy(new Error(`Timed out fetching ${u} after 20s`))
    }, 20_000)
    req.on('error', (e) => {
      clearTimeout(timer)
      reject(e)
    })
    req.end()
  })
}

/**
 * Fetch an http(s) URL with the SSRF guard, shared by knowledge_ingest
 * (loadIngestText) and learn_url. Follows redirects MANUALLY, re-validating
 * every hop: a public URL that 302s to http://127.0.0.1/ is the classic bypass
 * of a pre-flight check. Numeric / hex IPv4 forms (http://2130706433/ =
 * 127.0.0.1) and IPv6 literals never belong to a knowledge source.
 * learn_url used to plain-fetch with redirect-following - the exact bypass
 * this engine already refused one call away (2026-10-26 sweep H3).
 */
async function fetchPublicUrl(
  url: string,
  opts?: { allowLoopback?: boolean },
): Promise<{ res: Response; finalUrl: string }> {
  let u = url
  let res: Response | null = null
  for (let hop = 0; hop <= 3; hop++) {
    let host: string
    try {
      host = new URL(u).hostname
    } catch {
      throw new Error(`Invalid URL: ${u}`)
    }
    // allowLoopback is an owner-click capability passed via ctx (see
    // ToolContext.allowLoopbackFetch) - never via tool input, which the model
    // composes. The per-hop re-validation and manual redirects stay on.
    if (!opts?.allowLoopback &&
        (/^\\d+$/.test(host) || /^0x[0-9a-f]+$/i.test(host) || host.startsWith('[') || PRIVATE_HOST_RE.test(host))) {
      throw new Error(`Refusing to fetch private/loopback host ${host} (SSRF guard)`)
    }
    let pinned: { address: string; family: number }[] | null = null
    if (!opts?.allowLoopback) {
      // A HOSTNAME has no private literal in it yet can resolve into private
      // space (127.0.0.1.nip.io, localhost., any attacker DNS). Resolve every
      // hop and refuse if ANY address is private - the regex above alone was
      // bypassable (2026-10-26 release hardening).
      const addrs = await dns.promises.lookup(host, { all: true, verbatim: true }).catch(() => [])
      if (addrs.length === 0) throw new Error(`Cannot resolve host ${host}`)
      const bad = addrs.find((a) => isPrivateAddress(a.address))
      if (bad) {
        throw new Error(`Refusing to fetch ${host}: resolves to ${bad.address} (SSRF guard)`)
      }
      // THE PIN (2026-10-26 release follow-up): these validated addresses are
      // the ONLY answers the connect may use. The guard's query and the
      // socket's connect now consume the SAME array - rebinding and multi-A
      // hop-picking both need a second, independent resolver query, and there
      // is no longer one.
      pinned = addrs
    }
    res = await guardedRequest(u, pinned)
    if (res.status < 300 || res.status >= 400) break
    const loc = res.headers.get('location')
    if (!loc) break
    u = new URL(loc, u).toString()
    res = null
  }
  if (!res) throw new Error('Too many redirects while fetching the URL')
  return { res, finalUrl: u }
}

"""

c = c[:i] + NEW + c[j:]
open(P, 'wb').write(c.replace('\n', '\r\n').encode('utf-8'))
print('FETCHPUBLICURL REWRITTEN')
