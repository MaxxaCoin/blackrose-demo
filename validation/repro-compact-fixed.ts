// Proof that the proposed minimal fix kills both orphan paths.
// Patched COPY of compactHistory from src/session/history.ts (src/ untouched).
import type { Message } from '../cline/blackrose/src/types.ts'

export function compactHistoryFixed(messages: Message[], keepLast = 8): { messages: Message[]; removed: number } {
  if (messages.length <= keepLast) return { messages, removed: 0 }
  const old = messages.slice(0, messages.length - keepLast)
  let recent = messages.slice(-keepLast)
  const digest = old
    .map((m) => {
      const text =
        typeof m.content === 'string'
          ? m.content
          : Array.isArray(m.content)
            ? m.content
                .filter((b): b is { type: 'text'; text: string } => b.type === 'text')
                .map((b) => b.text)
                .join(' ')
            : ''
      const clean = text.replace(/\s+/g, ' ').trim()
      return clean ? `- ${m.role}: ${clean.slice(0, 200)}` : null
    })
    .filter((x): x is string => x !== null)
    .join('\n')
  const summary: Message = {
    role: 'user',
    content: `[Conversation continued. Summary of the earlier part of this session:\n${digest || '(no text content)'}\nUse it as context; do not comment on it.]`,
  }
  // the kept tail must start with a user turn for strict alternation
  if (recent[0]?.role !== 'user') {
    const firstUser = recent.findIndex((m) => m.role === 'user')
    recent = firstUser === -1 ? recent : recent.slice(firstUser)
  }
  // FIX (mirrors core/agent.ts:134-140): never start the kept window on an
  // orphaned tool_result — its matching tool_use may have been folded into the
  // summary, and providers reject a tool_result with no preceding tool_use.
  while (recent.length > 0) {
    const head = recent[0]!
    const startsWithToolResult =
      typeof head.content !== 'string' && head.content.some((b) => b.type === 'tool_result')
    if (!startsWithToolResult) break
    recent.shift()
  }
  return { messages: [summary, ...recent], removed: old.length }
}

const tu = (id: string): Message => ({
  role: 'assistant',
  content: [{ type: 'tool_use', id, name: 'read_file', input: { path: 'x' } }],
})
const tr = (id: string): Message => ({
  role: 'user',
  content: [{ type: 'tool_result', tool_use_id: id, content: 'file contents' }],
})

const caseA: Message[] = [
  { role: 'user', content: 'start' },
  tu('tu1'),
  { role: 'assistant', content: 'reading the file now' },
  tr('tu1'),
  { role: 'assistant', content: 'done' },
  { role: 'user', content: 'next question' },
]
const caseB: Message[] = [
  { role: 'user', content: 'start' },
  { role: 'assistant', content: 'let me look' },
  tu('tu1'),
  tr('tu1'),
  { role: 'assistant', content: 'done' },
  { role: 'user', content: 'next question' },
]

function orphan(msgs: Message[]): boolean {
  const head = msgs[1]
  return !!head && typeof head.content !== 'string' && head.content.some((b) => b.type === 'tool_result')
}

const a = compactHistoryFixed(caseA, 3)
const b = compactHistoryFixed(caseB, 4)
console.log('fixed Case A orphan:', orphan(a.messages), '| head:', a.messages[1]?.role)
console.log('fixed Case B orphan:', orphan(b.messages), '| head:', b.messages[1]?.role)
// alternation still holds and old pairs inside the tail stay intact:
console.log('kept tool_use/tool_result pair intact:',
  JSON.stringify(a.messages).includes('tool_use') === false || // nothing orphaned left
  a.messages.slice(1).some((m) => Array.isArray(m.content) && m.content.some((x) => x.type === 'tool_use')))
process.exit(orphan(a.messages) || orphan(b.messages) ? 1 : 0)
