"""DNS-rebinding fix (release follow-up): pin the connect to the validated IPs.

In fetchPublicUrl, the pre-flight dns.promises.lookup and the TCP connect are
TWO independent OS queries; an attacker DNS with TTL 0 answers public to the
first and private to the second (reproduced live 2026-10-26). Node's fetch
exposes no lookup hook (undici #421) and undici is off-limits (zero-dep), so
the guarded fetch moves to node:http/https.request whose `lookup` option
reaches net/tls.connect. The hook answers ONLY from the validated array.
"""
import sys

P = r'C:\Users\pc\Desktop\BlackRose\cline\blackrose\src\tools\knowledge.ts'
c = open(P, 'rb').read().decode('utf-8').replace('\r\n', '\n')


def rep(old, new, label):
    global c
    n = c.count(old)
    if n != 1:
        print(f'FAIL {label}: found {n}')
        sys.exit(1)
    c = c.replace(old, new)
    print(f'ok {label}')


# 1. imports
rep(
    "import fs from 'node:fs'\nimport dns from 'node:dns'\nimport net from 'node:net'\n",
    "import fs from 'node:fs'\nimport dns from 'node:dns'\nimport http from 'node:http'\nimport https from 'node:https'\nimport net from 'node:net'\nimport { Readable } from 'node:stream'\n",
    'imports')

# 2. guarded fetch + pinned lookup, inserted before fetchPublicUrl
ANCHOR = "/**\n * Fetch an http(s) URL with the SSRF guard, shared by knowledge_ingest"
assert c.count(ANCHOR) == 1, 'anchor'

GUARD = ANCHOR.replace(
    "async function fetchPublicUrl(",
    "XXX",
)
NEW_HEAD = """/**
 * The SSRF-validated fetch: an http(s) request whose DNS lookup is PINNED to
 * the addresses the guard just validated. The pre-flight dns.promises.lookup
 * and the TCP connect are two independent OS getaddrinfo queries - attacker
 * DNS with TTL 0 answers public to the first and private to the second
 * (classic rebinding; reproduced live 2026-10-26 with learn_url landing on a
 * loopback server while the guard saw 93.184.216.34). Node's fetch exposes no
 * lookup hook (undici #421) and undici itself is off-limits (zero-dep), so the
 * guarded fetch goes through node:http/https.request, whose `lookup` option
 * reaches net/tls.connect. addrs === null (the owner's allowLoopbackFetch
 * capability) resolves normally - unchanged behaviour for that path.
 */
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
  ms = 20_000,
): Promise<Response> {
  const parsed = new URL(u)
  const mod = parsed.protocol === 'https:' ? https : http
  return await new Promise<Response>((resolve, reject) => {
    // The URL stays the HOSTNAME form (SNI/certificate check still see the real
    // host); only the DNS answer is pinned. options are passed straight through:
    // `lookup` reaches net/tls.connect, which then never queries the resolver.
    const req = mod.request(
      parsed,
      {
        method: 'GET',
        headers: { 'user-agent': 'Mozilla/5.0 (BlackRose personal assistant)' },
        ...(pinned ? { lookup: pinnedLookup(pinned) } : {}),
      },
      (inc) => {
        const headers = new Headers()
        for (const [k, v] of Object.entries(inc.headers)) {
          if (Array.isArray(v)) v.forEach((vv) => headers.append(k, String(vv)))
          else if (typeof v === 'string') headers.set(k, v)
        }
        const body = Readable.toWeb(inc) as unknown as ReadableStream
        resolve(new Response(body, { status: inc.statusCode ?? 0, headers }))
      },
    )
    req.on('error', (e) => reject(e))
    const timer = setTimeout(() => {
      req.destroy(new Error(`Timed out fetching ${u} after 20s`))
    }, 20_000)
    req.on('response', () => clearTimeout(timer))
    req.end()
  })
}

"""
c = c.replace(ANCHOR, GUARD + ANCHOR, 1)
open(P, 'wb').write(c.replace('\n', '\r\n').encode('utf-8'))
print('GUARD HEAD APPLIED')
