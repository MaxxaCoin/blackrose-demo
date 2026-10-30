// Probe: which resolution hook does global fetch (undici) actually call at connect time?
import dns from 'node:dns'
import net from 'node:net'

const dl = dns.lookup
dns.lookup = function (host, ...rest) { console.log('[dns.lookup called]', host); return dl.call(dns, host, ...rest) }
const nc = net.connect
net.connect = function (...a) { console.log('[net.connect called]'); return nc.apply(net, a) }

try {
  const res = await fetch('http://localhost./x') // 'localhost.' resolves via getaddrinfo to 127.0.0.1; connection to :80 will likely fail - we only care about which hooks fire
  await res.text().catch(() => {})
} catch (e) { console.log('fetch error:', e.cause ? e.cause.code ?? e.cause.message : e.message) }
setTimeout(() => process.exit(0), 3000)
