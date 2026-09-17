// Determine whether the KiraAI account can actually serve paid requests:
// 1) probe likely balance endpoints (free), 2) if none exists, ONE 8-token
// chat call (negligible cost) purely to see billing/availability behavior.
import fs from 'node:fs'
const base = process.env.KIRA_BASE_URL || 'https://kiraai.vn/api/v1'
const model = process.env.KIRA_MODEL || 'qwen3.8-flash'
const key = fs.readFileSync('C:/Users/pc/Documents/kira_api_key.txt', 'utf8').trim()
const headers = { Authorization: 'Bearer ' + key, 'Content-Type': 'application/json' }

for (const p of ['/balance', '/credits', '/me', '/user', '/account', '/billing/credits']) {
  try {
    const r = await fetch(base + p, { headers })
    const text = await r.text()
    let summary = text.slice(0, 200).replace(/\s+/g, ' ')
    if (r.status === 404 || r.status === 405) { console.log(`[${p}] HTTP ${r.status} (no such endpoint)`); continue }
    console.log(`[${p}] HTTP ${r.status} :: ${summary}`)
  } catch (e) { console.log(`[${p}] ERROR ${String(e?.message || e).slice(0, 120)}`) }
}

console.log('--- single minimal chat call (max_tokens=8) on ' + model + ' ---')
try {
  const r = await fetch(base + '/chat/completions', {
    method: 'POST', headers,
    body: JSON.stringify({ model, messages: [{ role: 'user', content: 'Say OK' }], max_tokens: 8 }),
  })
  const j = await r.json().catch(() => null)
  const content = j?.choices?.[0]?.message?.content
  console.log(`HTTP ${r.status} :: error=${j?.error ? JSON.stringify(j.error).slice(0, 220) : 'none'} :: content=${JSON.stringify(content ?? null).slice(0, 120)} :: usage=${JSON.stringify(j?.usage ?? null)}`)
} catch (e) { console.log('CHAT ERROR ' + String(e?.message || e).slice(0, 200)) }
console.log('BALANCE_PROBE_DONE')
