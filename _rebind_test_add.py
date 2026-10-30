"""Regression test: DNS rebinding is dead — the connect consumes the validated IPs."""
import sys

P = r'C:\Users\pc\Desktop\BlackRose\cline\blackrose\src\audit-sweep2.test.ts'
c = open(P, 'rb').read().decode('utf-8')

if 'rebind.attacker.example' in c:
    print('TEST ALREADY PRESENT')
    sys.exit(0)

# add node:http + node:dns imports
OLD_IMP = "import { learnUrlTool, isPrivateAddress } from './tools/knowledge.ts'"
NEW_I = ("import dns from 'node:dns'\n"
         "import http from 'node:http'\n"
         "import { learnUrlTool, isPrivateAddress } from './tools/knowledge.ts'")
n = c.count(OLD_IMP)
assert n == 1, f'import anchor: {n}'
c = c.replace(OLD_IMP, NEW_I)
print('ok imports')

TEST = """
// ---------------------------------------------------------------------------
// 2026-10-26 release follow-up: DNS rebinding between the guard's lookup and
// the TCP connect. The guard resolved+validated one query; the connect used to
// re-resolve independently (undici → net.connect), so attacker DNS with TTL 0
// answered public to the guard and 127.0.0.1 to the socket — reproduced live
// pre-fix (the loopback server below WAS hit). The guarded fetch now pins the
// connect to the validated addresses via an http(s) `lookup` hook, so there is
// no second, independent resolver query to attack.
// ---------------------------------------------------------------------------
test('learn_url: a rebound hostname cannot land the connect on a private address', async () => {
  const ATTACK_HOST = 'rebind.attacker.example' // never resolves in real DNS
  let hit: { url?: string } | null = null
  const server = (await import('node:http')).createServer((req, res) => {
    hit = { url: req.url }
    res.setHeader('content-type', 'text/html')
    res.end('<html><body>INTERNAL SECRET PAGE</body></html>')
  })
  await new Promise<void>((ok) => server.listen(0, '127.0.0.1', ok))
  const port = (server.address() as { port: number }).port

  // Attacker authoritative DNS, TTL 0: two queries, two different answers.
  const origPromises = dns.promises.lookup.bind(dns.promises)
  ;(dns.promises as { lookup: unknown }).lookup = async (host: string) =>
    host === ATTACK_HOST ? [{ address: '93.184.216.34', family: 4 }] : []
  const origLookup = dns.lookup
  const rebound = function (host: string, opts: unknown, cb: unknown) {
    if (typeof opts === 'function') { cb = opts as never; opts = {} }
    if (host === ATTACK_HOST) {
      const addr = { address: '127.0.0.1', family: 4 }
      const cbf = cb as (e: Error | null, a: unknown, f?: number) => void
      const all = (opts as { all?: boolean } | undefined)?.all === true
      process.nextTick(() => cbF(asNever)) // placeholder replaced below
      return
    }
    return origLookup.call(dns, host, opts as never, cb as never)
  }
  void origLookup
  void server
  void hit
  void TESTMARK
})
"""
print('TEMPLATE ONLY - not final')
