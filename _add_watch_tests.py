"""Append single-watch tests to src/tools/telegram.test.ts."""
import sys

P = r'src\tools\telegram.test.ts'
c = open(P, 'rb').read().decode('utf-8')

if 'one watch per data dir' in c:
    print('skip: tests already present')
    sys.exit(0)

block = (
    "\r\n"
    "// ---------------------------------------------------------------------------\r\n"
    "// 2026-10-26 NEXT WORK item 8: ONE watch per data dir. Two hosts long-polling\r\n"
    "// getUpdates on the same bot token produce 409 conflicts and split or\r\n"
    "// duplicated updates. The watch now owns an instanceLock role for its whole\r\n"
    "// life; a second host gets an inert handle and a reason.\r\n"
    "// ---------------------------------------------------------------------------\r\n"
    "test('one watch per data dir: a second watch is refused with a reason and never polls', withCtx(async (ctx) => {\r\n"
    "  const events: string[] = []\r\n"
    "  const first = startTelegramWatch({ dataDir: ctx.dataDir, cwd: ctx.cwd, onEvent: (m) => events.push(m) })\r\n"
    "  try {\r\n"
    "    const secondEvents: string[] = []\r\n"
    "    const second = startTelegramWatch({ dataDir: ctx.dataDir, cwd: ctx.cwd, onEvent: (m) => secondEvents.push(m) })\r\n"
    "    try {\r\n"
    "      assert.match(secondEvents.join('\\n'), /telegram watch NOT started/)\r\n"
    "      assert.match(secondEvents.join('\\n'), /another BlackRose host owns the watch/)\r\n"
    "      // The refused handle is inert: runOnce must not deliver anything.\r\n"
    "      await second.runOnce()\r\n"
    "    } finally {\r\n"
    "      second.stop()\r\n"
    "    }\r\n"
    "  } finally {\r\n"
    "    first.stop()\r\n"
    "  }\r\n"
    "}))\r\n"
    "\r\n"
    "test('one watch per data dir: stopping the owner frees the role for the next host', withCtx(async (ctx) => {\r\n"
    "  const first = startTelegramWatch({ dataDir: ctx.dataDir, cwd: ctx.cwd })\r\n"
    "  first.stop()\r\n"
    "  const events: string[] = []\r\n"
    "  const second = startTelegramWatch({ dataDir: ctx.dataDir, cwd: ctx.cwd, onEvent: (m) => events.push(m) })\r\n"
    "  second.stop()\r\n"
    "  assert.equal(events.join('\\n').includes('telegram watch NOT started'), false,\r\n"
    "    'after the owner stops, the role must be free (no refusal event)')\r\n"
    "}))\r\n"
)

c = c.rstrip('\r\n') + '\r\n' + block
open(P, 'wb').write(c.encode('utf-8'))
print('ok: 2 single-watch tests appended')
