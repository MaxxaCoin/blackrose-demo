// Tool-call roundtrip probe for OpenRouter + Groq free models.
// Verifies the exact path the BlackRose openai adapter uses:
//   POST /chat/completions with tools + tool_choice=auto → native tool_calls back.
// Keys are read from Documents/*.txt and NEVER printed.
import fs from 'node:fs'

const gateways = [
  {
    name: 'openrouter',
    base: 'https://openrouter.ai/api/v1',
    key: fs.readFileSync('C:/Users/pc/Documents/openrouter_api_key.txt', 'utf8').trim(),
    models: process.argv.slice(2).filter((m) => !m.startsWith('groq=')),
    extraHeaders: { 'HTTP-Referer': 'http://localhost:8788', 'X-Title': 'BlackRose' },
  },
  {
    name: 'groq',
    base: 'https://api.groq.com/openai/v1',
    key: fs.readFileSync('C:/Users/pc/Documents/groq_api_key.txt', 'utf8').trim(),
    models: process.argv.slice(2)
      .filter((m) => m.startsWith('groq='))
      .map((m) => m.slice(5)),
    extraHeaders: {},
  },
]

const tools = [
  {
    type: 'function',
    function: {
      name: 'write_file',
      description: 'Write a file to disk',
      parameters: {
        type: 'object',
        properties: { path: { type: 'string' }, content: { type: 'string' } },
        required: ['path', 'content'],
      },
    },
  },
]

async function probeModel(gw, model) {
  const headers = { 'content-type': 'application/json', authorization: `Bearer ${gw.key}`, ...gw.extraHeaders }
  // 1) native tool_calls
  const t0 = Date.now()
  const res = await fetch(`${gw.base}/chat/completions`, {
    method: 'POST',
    headers,
    body: JSON.stringify({
      model,
      max_tokens: 1024,
      tool_choice: 'auto',
      tools,
      messages: [{ role: 'user', content: 'Use the write_file tool to create hello.txt containing the word hi.' }],
    }),
  })
  const ms = Date.now() - t0
  const body = await res.json()
  if (!res.ok) {
    console.log(`[FAIL] ${model} :: HTTP ${res.status} :: ${JSON.stringify(body).slice(0, 220)}`)
    return
  }
  const msg = body.choices?.[0]?.message
  const tc = msg?.tool_calls?.[0]
  if (tc) {
    console.log(`[OK] native tool_calls :: ${model} :: ${tc.function?.name} args=${tc.function?.arguments} :: wall_ms=${ms}`)
  } else {
    console.log(`[WARN] no native tool_calls :: ${model} :: content="${String(msg?.content ?? '').slice(0, 160)}" :: wall_ms=${ms}`)
  }
  // 2) plain chat (no tools) — proves the tools-only-when-present rule works
  const t1 = Date.now()
  const res2 = await fetch(`${gw.base}/chat/completions`, {
    method: 'POST',
    headers,
    body: JSON.stringify({
      model,
      max_tokens: 200,
      messages: [{ role: 'user', content: 'Reply with exactly: ROUNDTRIP_OK' }],
    }),
  })
  const body2 = await res2.json()
  const ms2 = Date.now() - t1
  if (!res2.ok) {
    console.log(`[FAIL] plain chat :: ${model} :: HTTP ${res2.status} :: ${JSON.stringify(body2).slice(0, 200)}`)
  } else {
    console.log(`[OK] plain chat :: ${model} :: "${String(body2.choices?.[0]?.message?.content ?? '').trim().slice(0, 80)}" :: wall_ms=${ms2}`)
  }
}

for (const gw of gateways) {
  if (gw.models.length === 0) continue
  console.log(`=== ${gw.name} ===`)
  for (const m of gw.models) {
    try {
      await probeModel(gw, m)
    } catch (e) {
      console.log(`[FAIL] ${m} :: ${e?.message ?? e}`)
    }
  }
}
console.log('TOOLPROBE_DONE')
