"""NEXT WORK item 9: /compact orphan-tool_result smoke checks + register vectors.test.ts."""
import sys

P = r'src\smoke.ts'
c = open(P, 'rb').read().decode('utf-8')


def rep(old, new, label):
    global c
    n = c.count(old)
    if n != 1:
        print(f'FAIL {label}: found {n}')
        sys.exit(1)
    c = c.replace(old, new)
    print(f'ok {label}')


rep(
    "import type { Message, ToolSchema, ToolUseBlock } from './types.ts'",
    "import type { Message, ToolResultBlock, ToolSchema, ToolUseBlock } from './types.ts'",
    'type import')

anchor = "  checks.push(['compactHistory is a no-op on short conversations', compactHistory(long.slice(0, 4), 8).removed === 0])\r\n"
assert c.count(anchor) == 1

addition = anchor + "\r\n" + \
"  // 2026-10-26 NEXT WORK item 9: /compact must not leave an orphan tool_result\r\n" + \
"  // at the head of the kept window — the summary folds its pairing tool_use\r\n" + \
"  // away and providers reject a leading/unpaired tool_result. The checks above\r\n" + \
"  // only used plain-text messages, which is exactly why the bug was missed.\r\n" + \
"  const orphan = (m: Message | undefined): boolean =>\r\n" + \
"    !!m && typeof m.content !== 'string' && (m.content as { type: string }[]).some((b) => b.type === 'tool_result')\r\n" + \
"  const toolUseA = { type: 'tool_use', id: 'tu_a', name: 'x', input: {} } as ToolUseBlock\r\n" + \
"  const caseA: Message[] = [\r\n" + \
"    { role: 'user', content: 'run the tool' },\r\n" + \
"    { role: 'assistant', content: [toolUseA] },\r\n" + \
"    { role: 'user', content: [{ type: 'tool_result', tool_use_id: 'tu_a' } as ToolResultBlock] },\r\n" + \
"    { role: 'assistant', content: 'done' },\r\n" + \
"    { role: 'user', content: 'second question' },\r\n" + \
"    { role: 'assistant', content: 'second answer' },\r\n" + \
"  ]\r\n" + \
"  const compA = compactHistory(caseA, 4)\r\n" + \
"  checks.push([\r\n" + \
"    '/compact drops a kept window that starts on an orphaned tool_result',\r\n" + \
"    !orphan(compA.messages[1]),\r\n" + \
"  ])\r\n" + \
"  const compB = compactHistory(\r\n" + \
"    [\r\n" + \
"      { role: 'user', content: 'earlier question' },\r\n" + \
"      { role: 'assistant', content: [toolUseA] },\r\n" + \
"      { role: 'user', content: [{ type: 'tool_result', tool_use_id: 'tu_a' } as ToolResultBlock] },\r\n" + \
"      { role: 'assistant', content: 'follow-up answer' },\r\n" + \
"      { role: 'user', content: 'final question' },\r\n" + \
"      { role: 'assistant', content: 'final answer' },\r\n" + \
"    ],\r\n" + \
"    4,\r\n" + \
"  )\r\n" + \
"  checks.push(['/compact re-anchor cannot land on a tool_result carrier', !orphan(compB.messages[1])])\r\n"

c = c.replace(anchor, addition, 1)
open(P, 'wb').write(c.encode('utf-8'))
print('SMOKE CHECKS APPLIED')

# register the new suite in npm test
P2 = r'package.json'
c = open(P2, 'rb').read().decode('utf-8')
old = 'src/core/undo-gc.test.ts src/config.test.ts'
new = 'src/core/undo-gc.test.ts src/memory/vectors.test.ts src/config.test.ts'
n = c.count(old)
if n != 1:
    print(f'FAIL package.json: found {n}')
    sys.exit(1)
c = c.replace(old, new)
open(P2 := r'package.json', 'wb').write(c.encode('utf-8'))
print('PACKAGE.JSON REGISTERED')
