"""M2 test: the shared helper now retries a transient EPERM/EACCES/EBUSY rename
(Windows AV/parallel-rename reality), so the assertion must allow >1 attempt -
its intent is 'the atomic rename was attempted and the failure was survivable',
not 'exactly once'."""
p = r'C:\Users\pc\Desktop\BlackRose\cline\blackrose\src\audit-fixes.test.ts'
c = open(p, 'rb').read().decode('utf-8').replace('\r\n', '\n')

old = "  assert.equal(renameCalls, 1, 'the atomic rename must have been attempted')"
new = ("  assert.ok(renameCalls >= 1,\n"
       "    'the atomic rename must have been attempted (the helper retries a transient EPERM a few times)')")
assert c.count(old) == 1
c = c.replace(old, new)
open(p, 'wb').write(c.replace('\n', '\r\n').encode('utf-8'))
print('M2 ASSERTION UPDATED')
