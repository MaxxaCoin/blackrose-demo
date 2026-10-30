// Read-only reproduction: does compactHistory() leave an orphan tool_result
// at the head of the compacted message array? Imports the REAL function from
// src/session/history.ts — no copy, no modification of src/.
import { compactHistory } from '../cline/blackrose/src/session/history.ts'
import type { Message } from '../cline/blackrose/src/types.ts'

const tu = (id: string): Message => ({
  role: 'assistant',
  content: [{ type: 'tool_use', id, name: 'read_file', input: { path: 'x' } }],
})
const tr = (id: string): Message => ({
  role: 'user',
  content: [{ type: 'tool_result', tool_use_id: id, content: 'file contents' }],
})

/** head-of-stream orphan check (mirrors core/agent.ts:134-140) */
function orphanAtHead(msgs: Message[]): Message | null {
  // skip the injected summary (index 0); check the first post-summary message
  const head = msgs[1]
  if (!head) return null
  if (typeof head.content !== 'string' && head.content.some((b) => b.type === 'tool_result')) return head
  return null
}

// Case A — boundary lands directly on the tool_result user message
const caseA: Message[] = [
  { role: 'user', content: 'start' },
  tu('tu1'),
  { role: 'assistant', content: 'reading the file now' },
  tr('tu1'), // ← becomes recent[0] when keepLast=3, messages.length=6
  { role: 'assistant', content: 'done, here is what it said' },
  { role: 'user', content: 'thanks, now do the other thing' },
]
const a = compactHistory(caseA, 3)
console.log('Case A (recent[0] is a tool_result user message):')
console.log(JSON.stringify(a.messages, null, 1))
console.log('orphan at head:', orphanAtHead(a.messages) !== null)

// Case B — re-anchor slice lands on the tool_result user message
const caseB: Message[] = [
  { role: 'user', content: 'start' },
  { role: 'assistant', content: 'let me look' },
  tu('tu1'),
  tr('tu1'), // ← firstUser inside the kept tail: re-anchor slices to here
  { role: 'assistant', content: 'done, here is what it said' },
  { role: 'user', content: 'thanks, now do the other thing' },
]
const b = compactHistory(caseB, 4)
console.log('\nCase B (re-anchor finds tool_result user first):')
console.log(JSON.stringify(b.messages, null, 1))
console.log('orphan at head:', orphanAtHead(b.messages) !== null)

const failed = orphanAtHead(a.messages) !== null || orphanAtHead(b.messages) !== null
console.log(failed ? '\nREPRODUCED: orphan tool_result survives /compact' : '\nno orphan — bug not reproduced')
process.exit(failed ? 1 : 0)
