// Probe OpenRouter: list models, filter free + tool-capable. Key never printed.
import fs from 'node:fs'

const key = fs.readFileSync('C:/Users/pc/Documents/openrouter_api_key.txt', 'utf8').trim()
const headers = {
  authorization: `Bearer ${key}`,
  'HTTP-Referer': 'http://localhost:8788',
  'X-Title': 'BlackRose',
}

const res = await fetch('https://openrouter.ai/api/v1/models', { headers })
console.log('MODELS HTTP', res.status)
const data = await res.json()
const models = (data.data ?? [])
console.log('total models:', models.length)

const isFree = (m) =>
  m.id?.endsWith(':free') ||
  (m.pricing && Number(m.pricing.prompt) === 0 && Number(m.pricing.completion) === 0)
const free = models.filter(isFree)
console.log('free-priced models:', free.length)

const toolCapable = free.filter((m) => (m.supported_parameters ?? []).includes('tools'))
console.log('free + tools in supported_parameters:', toolCapable.length)
const sorted = toolCapable.sort((a, b) => (b.created ?? 0) - (a.created ?? 0))
for (const m of sorted.slice(0, 24)) {
  console.log(
    `${m.id} | ctx=${m.context_length ?? '?'} | params=[${(m.supported_parameters ?? []).join(',')}]`,
  )
}
console.log('---chat probe---')
const pick = process.argv[2]
if (pick) {
  const t0 = Date.now()
  const chat = await fetch('https://openrouter.ai/api/v1/chat/completions', {
    method: 'POST',
    headers,
    body: JSON.stringify({
      model: pick,
      max_tokens: 900,
      messages: [
        { role: 'user', content: 'Reply with exactly: OPENROUTER_OK' },
      ],
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
console.log('OPENROUTER_PROBE_DONE')
