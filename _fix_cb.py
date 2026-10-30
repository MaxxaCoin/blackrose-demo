import sys

P = r'src\tools\knowledge.ts'
c = open(P, 'rb').read().decode('utf-8').replace('\r\n', '\n')
old = '      process.nextTick(() => callback(err))'
new = "      process.nextTick(() => callback(err, '', 4))"
n = c.count(old)
assert n == 1, n
c = c.replace(old, new)
open(P, 'wb').write(c.replace('\n', '\r\n').encode('utf-8'))
print('FIXED')
