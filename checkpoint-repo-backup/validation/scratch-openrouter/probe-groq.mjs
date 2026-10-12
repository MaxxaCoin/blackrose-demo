// Probe Groq: list models (OpenAI protocol at https://api.groq.com/openai/v1). Key never printed.
import fs from 'node:fs'

const key = fs.readFileSync('C:/Users/pc/Documents/groq_api_key.txt', 'utf8').trim()
const base = 'https://api.groq.com/openai/v1'
const headers = { authorization: `Bearer ${key}` }

const res = await fetch(`${base}/models`, { headers })
console.log('MODELS HTTP', res.status)
const data = await res.json()
const models = (data.data ?? [])
console.log('total models:', models.length)
for (const m of models) {
  console.log(`${m.id} | ctx=${m.context_window ?? '?'} | active=${m.active ?? '?'}`)
}
console.log('---chat probe---')
const pick = process.argv[2]
if (pick) {
  const t0 = Date.now()
  const chat = await fetch(`${base}/chat/completions`, {
    method: 'POST',
    headers,
    body: JSON.stringify({
      model: pick,
      max_tokens: 900,
      messages: [{ role: 'user', content: 'Reply with exactly: GROQ_OK' }],
    }),
  })
  const body = await chat.json()
  const ms = Date.now() - t0
  if (!chat.ok) {
    console.log('CHAT HTTP', chat.status, JSON.stringify(body).slice(0, 300))
  } else {
    console.log('CHAT HTTP', chat.status, `wall_ms=${ms}`)
    console.log('reply:', body.choices?.[0]?.message?.content)
    console.log('usage:', JSON.stringify(body.usage ?? {}))
  }
}
console.log('GROQ_PROBE_DONE')
