// Live validation of the SHIPPING BlackRose openai adapter against real gateways.
// Mirrors core/agent.ts exactly: call → tool_use → execute → tool_result → call → text.
// Keys are read from Documents/*.txt and NEVER printed.
import fs from 'node:fs'
import path from 'node:path'
import { openaiClient } from '../../cline/blackrose/src/llm/openai.ts'
import { resilientClient } from '../../cline/blackrose/src/llm/resilient.ts'

const scratch = path.dirname(new URL(import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1'))
const workDir = path.join(scratch, 'live')
fs.mkdirSync(workDir, { recursive: true })

const SYSTEM = 'You are BlackRose, a precise agent. Use the provided tools when asked to act on files.'
const schemas = [
  {
    name: 'write_file',
    description: 'Write text content to a file path',
    input_schema: {
      type: 'object',
      properties: { path: { type: 'string' }, content: { type: 'string' } },
      required: ['path', 'content'],
    },
  },
  {
    name: 'read_file',
    description: 'Read a text file and return its content',
    input_schema: {
      type: 'object',
      properties: { path: { type: 'string' } },
      required: ['path'],
    },
  },
]

function execTool(name, input) {
  const p = path.join(workDir, String(input.path ?? 'unnamed'))
  if (name === 'write_file') {
    fs.writeFileSync(p, String(input.content ?? ''), 'utf8')
    return `OK: wrote ${Buffer.byteLength(String(input.content ?? ''))} bytes to ${input.path}`
  }
  if (name === 'read_file') {
    return fs.readFileSync(p, 'utf8')
  }
  return `Unknown tool: ${name}`
}

async function agentRoundtrip(label, client) {
  console.log(`=== ${label} (${client.model}) ===`)
  const messages = [
    {
      role: 'user',
      content:
        'Create the file live-hello.txt with the exact content "hello from blackrose" using write_file. Then read it back with read_file and tell me what it says.',
    },
  ]
  const t0 = Date.now()
  let sawToolUse = 0
  let toolOk = false
  let finalText = ''
  for (let turn = 0; turn < 6; turn++) {
    const r = await client.call(SYSTEM, messages, schemas)
    const tus = r.content.filter((b) => b.type === 'tool_use')
    const text = r.content.filter((b) => b.type === 'text').map((b) => b.text).join(' ').trim()
    if (text) console.log(`[..] turn${turn + 1} text: "${text.slice(0, 100)}"`)
    if (tus.length === 0) {
      finalText = text
      break
    }
    messages.push({ role: 'assistant', content: r.content })
    const results = []
    for (const tu of tus) {
      sawToolUse++
      console.log(`[..] turn${turn + 1} tool_use :: ${tu.name} ${JSON.stringify(tu.input).slice(0, 90)}`)
      let out = ''
      try {
        out = execTool(tu.name, tu.input)
        if (tu.name === 'write_file') {
          const saved = fs.readFileSync(path.join(workDir, String(tu.input.path ?? '')), 'utf8')
          if (saved.includes('hello from blackrose')) toolOk = true
        }
      } catch (e) {
        out = `Tool failed: ${e.message}`
      }
      results.push({ type: 'tool_result', tool_use_id: tu.id, content: out })
    }
    messages.push({ role: 'user', content: results })
  }
  const ms = Date.now() - t0
  const okText = finalText.toLowerCase().includes('hello from blackrose')
  console.log(toolOk ? '[OK] write_file executed, file content verified on disk' : '[FAIL] file content wrong')
  console.log(`[OK] final text :: "${finalText.slice(0, 140)}"`)
  console.log(`[${okText && toolOk && sawToolUse >= 2 ? 'PASS' : 'WARN'}] ${label}: tool_uses=${sawToolUse}, full roundtrip in ${ms}ms`)
}

const openrouter = resilientClient(
  openaiClient({
    apiKey: fs.readFileSync('C:/Users/pc/Documents/openrouter_api_key.txt', 'utf8').trim(),
    model: process.env.PROBE_OR_MODEL ?? 'nvidia/nemotron-3-super-120b-a12b:free',
    baseUrl: 'https://openrouter.ai/api/v1',
    attribution: { siteUrl: 'http://localhost:8788', siteName: 'BlackRose' },
  }),
  { onRetry: (a, d, e) => console.log(`[retry ${a} in ${d}ms] ${(e instanceof Error ? e.message : String(e)).slice(0, 90)}`) },
)
const groq = resilientClient(
  openaiClient({
    apiKey: fs.readFileSync('C:/Users/pc/Documents/groq_api_key.txt', 'utf8').trim(),
    model: process.env.PROBE_GROQ_MODEL ?? 'openai/gpt-oss-120b',
    baseUrl: 'https://api.groq.com/openai/v1',
  }),
  { onRetry: (a, d, e) => console.log(`[retry ${a} in ${d}ms] ${(e instanceof Error ? e.message : String(e)).slice(0, 90)}`) },
)

await agentRoundtrip('openrouter', openrouter)
await agentRoundtrip('groq', groq)
console.log('LIVE_AGENT_PROBE_DONE')
