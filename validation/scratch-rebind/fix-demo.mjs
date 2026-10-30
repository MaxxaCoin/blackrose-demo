// Fix-shape demo: prove that a custom lookup hook defeats the rebinding.
// After the dns.promises.lookup validates the host, we pass a `lookup` option
// to http.request that NEVER re-resolves — it returns the pre-validated address.
// This is the minimal fix implementable with Node builtins only.
import dns from 'node:dns'
import http from 'node:http'
import { Readable } from 'node:stream'

const ATTACK_HOST = 'rebind.attacker.example'
let hit = null

const server = http.createServer((req, res) => {
  hit = { url: req.url }
  res.end('INTERNAL')
})
await new Promise((ok) => server.listen(0, '127.0.0.1', ok))
const port = server.address().port

// Simulate the attacker DNS: returns 127.0.0.1 for all queries (connect time).
const origLookup = dns.lookup
dns.lookup = function (host, opts, cb) {
  if (typeof opts === 'function') { cb = opts; opts = {} }
  if (host === ATTACK_HOST) {
    const addr = { address: '127.0.0.1', family: 4 }
    process.nextTick(() => cb(null, opts?.all ? [addr] : addr.address, opts?.all ? undefined : addr.family))
    return
  }
  return origLookup.call(dns, host, opts, cb)
}

// --- THE FIX ---
// Simulate the "resolve once, validate, pin" step inside fetchPublicUrl.
// In the real fix, this lookup would be closed over `validatedAddrs` from the
// earlier dns.promises.lookup (knowledge.ts:337).  Here we show the pinned
// lookup that returns the public address it was handed — never re-resolves.
function pinnedLookup (resolvedAddrs) {
  return function (hostname, opts, cb) {
    if (typeof opts === 'function') { cb = opts; opts = {} }
    // For Happy Eyeballs (autoSelectFamily, all:true): return the array we were given.
    if (opts?.all) {
      process.nextTick(() => cb(null, resolvedAddrs))
      return
    }
    // Single-address case (shouldn't occur once autoSelectFamily=true, but safe):
    process.nextTick(() => cb(null, resolvedAddrs[0].address, resolvedAddrs[0].family))
  }
}

const validatedAddrs = [{ address: '93.184.216.34', family: 4 }] // from dns.promises.lookup
const req = http.request(`http://${ATTACK_HOST}:${port}/secret`, {
  lookup: pinnedLookup(validatedAddrs),   // ← the pinning hook
  timeout: 5000,
}, (res) => {
  let body = ''
  res.on('data', (c) => { body += c })
  res.on('end', () => {
    server.close()
    if (hit) {
      console.log('FAIL: with PINNED lookup the request STILL reached loopback.')
      console.log('      The lookup hook returned public addr but undici still used 127.0.0.1')
      process.exit(1)
    } else {
      console.log('PASS: pinned lookup routed to', validatedAddrs[0].address,
                  '— no hit on loopback server. Rebinding defeated.')
      process.exit(0)
    }
  })
})
req.on('error', (e) => {
  console.log('connect to', validatedAddrs[0].address, 'failed (expected — no service there):', e.code)
  console.log('PASS: pinned lookup connected to validated public IP, never reached loopback.')
  console.log('      Rebinding is defeated by the lookup hook.')
  server.close()
  process.exit(0)
})
req.end()
