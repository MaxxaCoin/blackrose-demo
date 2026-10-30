"""Make the concurrency test deterministic: use writeFileAtomic (temp name is
computed synchronously at entry, so all writers in one tick share a millisecond;
the mkdir flavour awaits first and spreads them out)."""
import sys

p = r'C:\Users\pc\Desktop\BlackRose\cline\blackrose\src\core\atomicFile.test.ts'
c = open(p, 'rb').read().decode('utf-8').replace('\r\n', '\n')

assert "import { writeFileAtomicAt, writeFileAtomicSync } from './atomicFile.ts'" in c
c = c.replace(
    "import { writeFileAtomicAt, writeFileAtomicSync } from './atomicFile.ts'",
    "import { writeFileAtomic, writeFileAtomicAt, writeFileAtomicSync } from './atomicFile.ts'")

OLD = """  const writes = Array.from({ length: 8 }, (_, i) =>
    writeFileAtomicAt(p, JSON.stringify({ writer: i, pad: 'x'.repeat(4096) })))"""
NEW = """  // writeFileAtomic, not the mkdir flavour: its temp name is computed
  // SYNCHRONOUSLY at entry, so every writer below shares one millisecond - the
  // exact collision the monotonic suffix exists for (the mkdir flavour awaits
  // first, which spreads the timestamps and would hide the race).
  const writes = Array.from({ length: 8 }, (_, i) =>
    writeFileAtomic(p, JSON.stringify({ writer: i, pad: 'x'.repeat(4096) })))"""
assert c.count(OLD) == 1
c = c.replace(OLD, NEW)
open(p, 'wb').write(c.replace('\n', '\r\n').encode('utf-8'))
print('test made deterministic')
