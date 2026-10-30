"""Fix the pinnedLookup signature to satisfy net.LookupFunction types."""
import sys

P = r'C:\Users\pc\Desktop\BlackRose\cline\blackrose\src\tools\knowledge.ts'
c = open(P, 'rb').read().decode('utf-8').replace('\r\n', '\n')

OLD = """function pinnedLookup(addrs: { address: string; family: number }[]): NonNullable<net.LookupFunction> {
  return (
    _hostname: string,
    options: { all?: boolean; family?: number },
    callback: (err: Error | null, address?: unknown, family?: number) => void,
  ) => {
    const usable = addrs.filter((a) => (options?.family ? a.family === options.family : true))"""

NEW = """function pinnedLookup(addrs: { address: string; family: number }[]): NonNullable<net.LookupFunction> {
  return (
    _hostname: string,
    options: { all?: boolean; family?: number | 'IPv4' | 'IPv6' },
    callback: (err: Error | null, address?: unknown, family?: number) => void,
  ) => {
    const fam = options?.family === 'IPv4' ? 4 : options?.family === 'IPv6' ? 6 : options?.family
    const usable = addrs.filter((a) => (fam ? a.family === fam : true))"""

n = c.count(OLD)
assert n == 1, f'anchor: {n}'
c = c.replace(OLD, NEW)
open(P, 'wb').write(c.replace('\n', '\r\n').encode('utf-8'))
print('LOOKUP TYPES FIXED')
