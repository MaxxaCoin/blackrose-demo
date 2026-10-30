p = r'C:\Users\pc\Desktop\BlackRose\cline\blackrose\src\core\atomicFile.test.ts'
c = open(p, 'rb').read().decode('utf-8').replace('\r\n', '\n')

if 'overlapping writers' in c:
    print('already present')
else:
    TEST = """
// ---------------------------------------------------------------------------
// 2026-10-26 release follow-up (unification): every hand-rolled writer now goes
// through this helper, so its temp-uniqueness assumption must hold under
// interleaving - the strong sites it replaced used pid+counter. Fire several
// concurrent async writes at ONE target: the winner must land a complete,
// parseable file and no temp debris may survive.
// ---------------------------------------------------------------------------
test('overlapping writers: the last write lands complete, with no temp debris', async () => {
  const dir = tmpDir()
  const p = path.join(dir, 'contended.json')
  const writes = Array.from({ length: 8 }, (_, i) =>
    writeFileAtomicAt(p, JSON.stringify({ writer: i, pad: 'x'.repeat(4096) })))
  await Promise.all(writes)
  const parsed = JSON.parse(fs.readFileSync(p, 'utf8')) as { writer: number; pad: string }
  assert.ok(parsed.writer >= 0 && parsed.writer < 8, 'the file holds ONE complete writer payload')
  assert.equal(parsed.pad.length, 4096, 'no torn or truncated content')
  const leftovers = fs.readdirSync(dir).filter((f) => f.includes('.tmp'))
  assert.deepEqual(leftovers, [], 'no temp debris after concurrent writes')
})
"""
    c = c.rstrip('\n') + '\n' + TEST
    open(p, 'wb').write(c.replace('\n', '\r\n').encode('utf-8'))
    print('test appended')
