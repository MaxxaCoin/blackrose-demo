"""Replace pinnedLookup with the cleanly-typed version."""
import sys

P = r'C:\Users\pc\Desktop\BlackRose\cline\blackrose\src\tools\knowledge.ts'
c = open(P, 'rb').read().decode('utf-8').replace('\r\n', '\n')

OLD = """function pinnedLookup(addrs: { address: string; family: number }[]): NonNullable<net.LookupFunction> {
  return (
    _hostname: string,
    options: { all?: boolean; family?: number | 'IPv4' | 'IPv6' },
    callback: (err: Error | null, address?: unknown, family?: number) => void,
  ) => {"""
NEW = """function pinnedLookup(addrs: { address: string; family: number }[]): NonNullable<net.LookupFunction> {
  return (_hostname, options, callback) => {"""

OLD2 = """    if (usable.length === 0) {
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
    })"""

NEW2 = """    if (usable.length === 0) {
      const err = new Error('no validated address usable for this connection (pinned SSRF lookup)') as NodeJS.ErrnoException
      err.code = 'EAI_AGAIN'
      process.nextTick(() => callback(err))
      return
    }
    process.nextTick(() => {
      if (options?.all) {
        // all:true → callback(null, [{address, family}...])
        callback(null, usable)
      } else {
        callback(null, usable[0]!.address, usable[0]!.family)
      }
    })"""

n = c.count(OLD)
assert n == 1, f'fn signature anchor: {n}'
c = c.replace(OLD, NEW)

n2 = c.count(OLD2)
assert n2 == 1, f'callback body anchor: {n}'
c = c.replace(OLD2, NEW2)

open(P, 'wb').write(c.replace('\n', '\r\n').encode('utf-8'))
print('PINNEDLOOKUP CLEAN')
