// Live validation of the SHIPPING BlackRose code against the user's OmniRoute
// combo ("BlackRose" → free models, auto-fallback inside OmniRoute).
//   1. raw OpenAI-protocol call: which upstream model answers the combo?
//   2. shipping openaiClient + resilientClient: full 2-tool agent roundtrip
//   3. routerClient: proves the chain (first route dead → next one serves)
// The key is read from Documents/omniroute_api_key.txt and NEVER printed.
import fs from 'node:fs'
import path from 'node:path'
import { openaiClient } from '../../cline/blackrose/src/llm/openai.ts'
import { resilientClient } from '../../cline/blackrose/src/llm/resilient.ts'
import { routerClient } from '../../cline/blackrose/src/llm/router.ts'

const BASE = process.env.OMNIROUTE_BASE ?? 'http://127.0.0.1:20128/v1'
const KEY = fs.readFileSync('C:/Users/pc/Documents/omniroute_api_key.txt', 'utf8').trim()
const MODEL = process.env.OMNIROUTE_MODEL ?? 'BlackRose'
const scratch = path.dirname(new URL(import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1'))
const workDir = path.join(scratch, 'live')
fs.mkdirSync(workDir, { recursive: true })

// 1. raw call — show the upstream model the combo resolved to
{
  const t0 = Date.now()
  const res = await fetch(`${BASE}/chat/completions`, {
    method: 'POST',
    headers: { authorization: `Bearer ${KEY}`, 'content-type': 'application/json' },
    body: JSON.stringify({ model: MODEL, messages: [{ role: 'user', content: 'Reply with exactly: OK' }], max_tokens: 10 }),
  })
  const j = await res.json()
  console.log(`[raw] HTTP ${res.status} in ${Date.now() - t0}ms — combo "${MODEL}" answered by upstream model: ${j.model}`)
  console.log(`[raw] content: ${JSON.stringify(j.choices?.[0]?.message?.content)}`)
}

const SYSTEM = 'You are BlackRose, a precise agent. Use the provided tools when asked to act on files.'
const schemas = [
  {
    name: 'write_file',
    description: 'Write text content to a file path',
    input_schema: { type: 'object', properties: { path: { type: 'string' }, content: { type: 'string' } }, required: ['path', 'content'] },
  },
  {
    name: 'read_file',
    description: 'Read a text file and return its content',
    input_schema: { type: 'object', properties: { path: { type: 'string' } }, required: ['path'] },
  },
]

function execTool(name, input) {
  const p = path.join(workDir, String(input.path ?? 'unnamed'))
  if (name === 'write_file') {
    fs.writeFileSync(p, String(input.content ?? ''), 'utf8')
    return `OK: wrote to ${input.path}`
  }
  if (name === 'read_file') return fs.readFileSync(p, 'utf8')
  return `Unknown tool: ${name}`
}

async function agentRoundtrip(label, client) {
  console.log(`\n=== ${label} (model ${client.model}) ===`)
  const messages = [
    {
      role: 'user',
      content:
        'Create the file omni-hello.txt with the exact content "hello from omniroute" using write_file. Then read it back with read_file and tell me what it says.',
    },
  ]
  const t0 = Date.now()
  let toolUses = 0
  let fileOk = false
  let finalText = ''
  for (let turn = 0; turn < 6; turn++) {
    const r = await client.call(SYSTEM, messages, schemas)
    const tus = r.content.filter((b) => b.type === 'tool_use')
    const text = r.content.filter((b) => b.type === 'text').map((b) => b.text).join(' ').trim()
    if (tus.length === 0) {
      finalText = text
      break
    }
    messages.push({ role: 'assistant', content: r.content })
    const results = []
    for (const tu of tus) {
      toolUses++
      console.log(`[..] tool_use :: ${tu.name} ${JSON.stringify(tu.input).slice(0, 90)}`)
      let out = ''
      try {
        out = execTool(tu.name, tu.input)
        if (tu.name === 'write_file' && fs.readFileSync(path.join(workDir, String(tu.input.path ?? '')), 'utf8').includes('hello from omniroute')) {
          fileOk = true
        }
      } catch (e) {
        out = `Tool failed: ${e.message}`
      }
      results.push({ type: 'tool_result', tool_use_id: tu.id, content: out })
    }
    messages.push({ role: 'user', content: results })
  }
  const ms = Date.now() - t0
  const okText = finalText.toLowerCase().includes('hello from omniroute')
  console.log(fileOk ? '[OK] write_file executed, file verified on disk' : '[FAIL] file content wrong')
  console.log(`[..] final: "${finalText.slice(0, 140)}"`)
  console.log(`[${okText && fileOk && toolUses >= 2 ? 'PASS' : 'WARN'}] ${label}: tool_uses=${toolUses}, ${ms}ms`)
  return okText && fileOk && toolUses >= 2
}

const omni = resilientClient(openaiClient({ apiKey: KEY, model: MODEL, baseUrl: BASE }), {
  onRetry: (a, d, e) => console.log(`[retry ${a} in ${d}ms] ${(e instanceof Error ? e.message : String(e)).slice(0, 90)}`),
})
const live = await agentRoundtrip('omniroute-combo', omni)

// 3. router fallback: a DEAD first route must hand off to the live OmniRoute
{
  const dead = openaiClient({ apiKey: KEY, model: MODEL, baseUrl: 'http://127.0.0.1:9/v1' })
  const router = routerClient([dead, omni], (m) => console.log(`  ↪ ${m}`))
  const r = await router.call(SYSTEM, [{ role: 'user', content: 'Reply with exactly: FALLBACK-OK' }], [])
  const text = r.content.filter((b) => b.type === 'text').map((b) => b.text).join(' ').trim()
  console.log(`[${text.includes('FALLBACK-OK') ? 'PASS' : 'WARN'}] router chain fell back to the live route: "${text.slice(0, 80)}"`)
}

console.log('\n' + (live ? 'OMNIROUTE PROBE PASS' : 'OMNIROUTE PROBE WARN'))