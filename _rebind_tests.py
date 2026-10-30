"""1) guardedRequest timeout becomes env-tunable (test speed + parity with
BLACKROSE_BRIDGE_TIMEOUT_MS). 2) Two regression tests for the DNS-rebind fix.
"""
import sys

K = r'C:\Users\pc\Desktop\BlackRose\cline\blackrose\src\tools\knowledge.ts'
c = open(K, 'rb').read().decode('utf-8').replace('\r\n', '\n')

OLD = """    const timer = setTimeout(() => {
      req.destroy(new Error(`Timed out fetching ${u} after 20s`))
    }, 20_000)"""
NEW = """    // Env-tunable like BLACKROSE_BRIDGE_TIMEOUT_MS: an empty value counts as
    // unset and junk falls back to the default (Number('') is 0, not NaN).
    const raw = Number(process.env.BLACKROSE_FETCH_TIMEOUT_MS ?? '')
    const timeoutMs = Number.isFinite(raw) && raw > 0 ? raw : 20_000
    const timer = setTimeout(() => {
      const shown = timeoutMs >= 1000 ? `${Math.round(timeoutMs / 1000)}s` : `${timeoutMs}ms`
      req.destroy(new Error(`Timed out fetching ${u} after ${shown}`))
    }, timeoutMs)"""
n = c.count(OLD)
assert n == 1, f'timer anchor: {n}'
c = c.replace(OLD, NEW)
open(K, 'wb').write(c.replace('\n', '\r\n').encode('utf-8'))
print('ok timeout env')

T = r'C:\Users\pc\Desktop\BlackRose\cline\blackrose\src\audit-sweep2.test.ts'
c = open(T, 'rb').read().decode('utf-8').replace('\r\n', '\n')

if 'rebind.attacker.example' not in c:
    OLD_IMP = "import { learnUrlTool, isPrivateAddress } from './tools/knowledge.ts'"
    NEW_I = ("import dns from 'node:dns'\n"
             "import http from 'node:http'\n"
             "import { learnUrlTool, isPrivateAddress } from './tools/knowledge.ts'")
    assert c.count(OLD_IMP) == 1
    c = c.replace(OLD_IMP, NEW_I)

    TESTS = """
// ---------------------------------------------------------------------------
// 2026-10-26 release follow-up: DNS rebinding between the guard's lookup and
// the TCP connect. The guard validated one query; the connect used to resolve
// INDEPENDENTLY (undici -> net.connect), so attacker DNS with TTL 0 answered
// public to the guard and 127.0.0.1 to the socket - reproduced live pre-fix
// (the loopback server here WAS reached and its content was learned). The
// guarded fetch now pins the connect to the validated addresses via an
// http(s) `lookup` hook: there is no second, independent resolver query.
// ---------------------------------------------------------------------------
test('learn_url: a rebound hostname cannot land the connect on a private address', async () => {
  const ATTACK_HOST = 'rebind.attacker.example' // never resolves in real DNS
  let hit: { url?: string } | null = null
  const server = http.createServer((req, res) => {
    hit = { url: req.url }
    res.setHeader('content-type', 'text/html')
    res.end('<html><body>INTERNAL SECRET PAGE</body></html>')
  })
  await new Promise<void>((ok) => server.listen(0, '127.0.0.1', ok))
  const port = (server.address() as { port: number }).port

  const origPromises = dns.promises.lookup
  const origLookup = dns.lookup
  const prevTimeout = process.env.BLACKROSE_FETCH_TIMEOUT_MS
  try {
    // Keep the test fast: the pinned connect has nowhere to go, so it must
    // fail on OUR deadline, not on the network's.
    process.env.BLACKROSE_FETCH_TIMEOUT_MS = '400'
    // Query #1 - the guard's dns.promises.lookup - sees a PUBLIC address.
    ;(dns.promises as unknown as { lookup: unknown }).lookup = async (host: string, opts?: unknown) =>
      host === ATTACK_HOST
        ? [{ address: '93.184.216.34', family: 4 }]
        : (origPromises as unknown as (h: string, o?: unknown) => Promise<unknown>).call(dns.promises, host, opts)
    // Query #2 - what the OLD connect used (net.connect's default dns.lookup) -
    // is the attacker's REBOUND answer: loopback.
    const patched = function (host: string, opts: unknown, cb: unknown): void {
      let options = opts
      let callback = cb
      if (typeof opts === 'function') { callback = opts; options = {} }
      if (host === ATTACK_HOST) {
        const addr = { address: '127.0.0.1', family: 4 }
        const all = (options as { all?: boolean } | undefined)?.all === true
        const cbf = callback as (e: Error | null, a: unknown, f?: number) => void
        process.nextTick(() => (all ? cbf(null, [addr]) : cbf(null, addr.address, addr.family)))
        return
      }
      ;(origLookup as unknown as (...a: unknown[]) => void).call(dns, host, options, callback)
    }
    ;(dns as unknown as { lookup: unknown }).lookup = patched

    const ctx = tmpCtx()
    const r = await learnUrlTool.run({ url: `http://${ATTACK_HOST}:${port}/secret` }, ctx)
    assert.equal(hit, null, 'the connect must never reach the rebound loopback address')
    assert.equal(r.isError, true, 'the fetch must fail honestly instead of reading the internal page')
    assert.ok(!r.content.includes('INTERNAL SECRET PAGE'), 'no internal content may enter the knowledge base')
  } finally {
    ;(dns.promises as unknown as { lookup: unknown }).lookup = origPromises
    ;(dns as unknown as { lookup: unknown }).lookup = origLookup
    if (prevTimeout === undefined) delete process.env.BLACKROSE_FETCH_TIMEOUT_MS
    else process.env.BLACKROSE_FETCH_TIMEOUT_MS = prevTimeout
    server.close()
  }
})

// The whole guarded fetch was replaced (fetch -> http/https.request + a pinned
// lookup + Response conversion), so the OWNER-CAPABILITY path - which resolves
// normally and must keep working end-to-end - is pinned here too: a loopback
// page through ctx.allowLoopbackFetch must learn successfully.
test('learn_url: the owner allowLoopbackFetch capability still reads a local page', async () => {
  const server = http.createServer((req, res) => {
    res.setHeader('content-type', 'text/html')
    res.end('<html><body><h1>Local notes</h1><p>The guarded request path works end to end.</p></body></html>')
  })
  await new Promise<void>((ok) => server.listen(0, '127.0.0.1', ok))
  const port = (server.address() as { port: number }).port
  try {
    const base = tmpCtx()
    const ctx = { ...base, allowLoopbackFetch: true } as ToolContext
    const r = await learnUrlTool.run({ url: `http://127.0.0.1:${port}/local` }, ctx)
    assert.equal(r.isError, false, r.content)
    assert.match(r.content, /Learned/)
  } finally {
    server.close()
  }
})
"""
    c = c.rstrip('\n') + '\n' + TESTS
    open(T, 'wb').write(c.replace('\n', '\r\n').encode('utf-8'))
    print('ok tests appended')
else:
    print('tests already present')
