import re

P = r'src\tools\telegram.test.ts'
c = open(P, 'rb').read().decode('utf-8')
old = "saveTelegramToken(ctx.dataDir, '123456:TEST-TOKEN-NOT-REAL')"
new = "saveTelegramToken(ctx.dataDir, '123456:TEST-TOKEN-NOT-REAL-0123456789abcdef')"
n = c.count(old)
assert n == 1, f'found {n}'
open(P, 'wb').write(c.replace(old, new).encode('utf-8'))
print('TOKEN FIXED')
