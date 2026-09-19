// Probe a provider's OpenAI-compatible free tier. Usage:
//   node probe-provider.mjs <label> <baseUrl> <keyFile> [model] [openaiModels=1]
// Prints ONLY: status, model count, free/cheap model ids, tool-call support.
// Keys are read from the file and NEVER printed.
import fs from 'node:fs'

const [label, baseUrl, keyFile, model, wantModels] = process.argv.slice(2)
if (!label || !baseUrl || !keyFile) {
  console.error('usage: node probe-provider.mjs <label> <baseUrl> <keyFile> [model] [openaiModels=1]')
  process.exit(2)
}
const key = fs.readFileSync(keyFile, 'utf8').trim()
const base = baseUrl.replace(/\/+$/, '')

console.log(`=== ${label} ===`)
if (wantModels === '1') {
  try {
    const r = await fetch(`${base}/models`, { headers: { authorization: `Bearer ${key}` } })
    const j = await r.json()
    const data = Array.isArray(j.data) ? j.data : []
    const ids = data.map((m) => m.id).filter(Boolean)
    const free = data
      .filter((m) => m.is_free || /:free$/.test(String(m.id)) || /free/i.test(String(m.name ?? '')))
      .map((m) => m.id)
      .filter(Boolean)
    console.log(`[models] HTTP ${r.status} · ${ids.length} total${free.length ? ` · free: ${free.slice(0, 8).join(', ')}${free.length > 8 ? '…' : ''}` : ''}`)
  } catch (e) {
    console.log(`[models] FAIL ${e instanceof Error ? e.message : String(e)}`)
  }
}

if (model) {
  const tool = {
    type: 'function',
    function: { name: 'probe_tool', description: 'Probe tool', parameters: { type: 'object', properties: { ok: { type: 'boolean' } }, required: ['ok'] } },
  }
  const body = {
    model,
    messages: [{ role: 'user', content: 'Call probe_tool with ok:true, then say DONE.' }],
    tools: [tool],
    max_tokens: 200,
  }
  try {
    const t0 = Date.now()
    const r = await fetch(`${base}/chat/completions`, {
      method: 'POST',
      headers: { authorization: `Bearer ${key}`, 'content-type': 'application/json' },
      body: JSON.stringify(body),
    })
    const j = await r.json()
    const msg = j.choices?.[0]?.message ?? {}
    const tc = msg.tool_calls?.[0]
    console.log(`[chat] HTTP ${r.status} in ${Date.now() - t0}ms · model=${j.model ?? model}`)
    console.log(`[chat] tool_calls: ${tc ? `${tc.function.name}(${tc.function.arguments})` : 'none'}`)
    console.log(`[chat] content: ${JSON.stringify(msg.content ?? '')}`)
  } catch (e) {
    console.log(`[chat] FAIL ${e instanceof Error ? e.message : String(e)}`)
  }
}
console.log(`${label.toUpperCase()} PROBE DONE`)