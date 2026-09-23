// Live probe of the SHIPPING Gemini native adapter (src/llm/gemini.ts).
// Tests plain chat + a full 2-tool agent roundtrip. Key read from disk, never printed.
import fs from 'node:fs'
import path from 'node:path'
import { geminiClient } from '../../cline/blackrose/src/llm/gemini.ts'

const workDir = path.join(process.cwd(), 'validation', 'scratch-gemini', 'live')
fs.mkdirSync(workDir, { recursive: true })

const KEY = fs.readFileSync('C:/Users/pc/Documents/google_ai_studio_api_key.txt', 'utf8').trim()
const MODEL = process.env.PROBE_GEMINI_MODEL ?? 'gemini-3-flash-preview'
const client = geminiClient({ apiKey: KEY, model: MODEL })

console.log('=== plain chat (model ' + MODEL + ') ===')
const r1 = await client.call('You are a precise assistant.', [{ role: 'user', content: 'Reply with exactly: OK' }], [])
const t1 = r1.content.filter((b) => b.type === 'text').map((b) => b.text).join(' ')
console.log('text:', JSON.stringify(t1))
console.log('stop_reason:', r1.stop_reason, '· usage:', JSON.stringify(r1.usage))

console.log('')
console.log('=== tool roundtrip ===')
const schemas = [
  { name: 'write_file', description: 'Write text to a file', input_schema: { type: 'object', properties: { path: { type: 'string' }, content: { type: 'string' } }, required: ['path', 'content'] } },
  { name: 'read_file', description: 'Read a file', input_schema: { type: 'object', properties: { path: { type: 'string' } }, required: ['path'] } },
]
const messages = [
  { role: 'user', content: 'Create the file gemini-hello.txt with the exact content "hello from gemini" using write_file. Then read it back and tell me what it says.' },
]
let toolUses = 0
let fileOk = false
let finalText = ''
for (let turn = 0; turn < 6; turn++) {
  const r = await client.call('You are BlackRose, a precise agent.', messages, schemas)
  const tus = r.content.filter((b) => b.type === 'tool_use')
  const text = r.content.filter((b) => b.type === 'text').map((b) => b.text).join(' ').trim()
  if (tus.length === 0) { finalText = text; break }
  messages.push({ role: 'assistant', content: r.content })
  const results = []
  for (const tu of tus) {
    toolUses++
    console.log('tool_use :: ' + tu.name + ' ' + JSON.stringify(tu.input).slice(0, 90))
    const p = path.join(workDir, String(tu.input.path ?? 'unnamed'))
    let out = ''
    if (tu.name === 'write_file') {
      fs.writeFileSync(p, String(tu.input.content ?? ''), 'utf8')
      out = 'OK: wrote ' + String(tu.input.content ?? '').length + ' bytes'
      if (fs.readFileSync(p, 'utf8').includes('hello from gemini')) fileOk = true
    } else if (tu.name === 'read_file') {
      out = fs.readFileSync(p, 'utf8')
    } else {
      out = 'Unknown tool: ' + tu.name
    }
    results.push({ type: 'tool_result', tool_use_id: tu.id, content: out })
  }
  messages.push({ role: 'user', content: results })
}
console.log('fileOk:', fileOk, '· toolUses:', toolUses)
console.log('final:', finalText.slice(0, 160))
console.log(fileOk && toolUses >= 2 && finalText.toLowerCase().includes('hello from gemini') ? 'GEMINI PROBE PASS' : 'GEMINI PROBE WARN')
