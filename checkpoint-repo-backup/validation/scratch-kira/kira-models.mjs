// List KiraAI models (id / free / status) — key optional for this endpoint.
import fs from 'node:fs'
const base = process.env.KIRA_BASE_URL || 'https://kiraai.vn/api/v1'
let headers = {}
try { headers = { Authorization: 'Bearer ' + fs.readFileSync('C:/Users/pc/Documents/kira_api_key.txt', 'utf8').trim() } } catch { /* anonymous ok */ }
const r = await fetch(base + '/models', { headers })
const j = await r.json()
const list = Array.isArray(j?.data) ? j.data : []
for (const m of list) {
  console.log(`${m.is_free ? 'FREE ' : 'PAID '} [${m.status ?? 'active'}] ${m.id} :: ${Array.isArray(m.tags) ? m.tags.join(',') : (m.tags ?? '')}`)
}
console.log('TOTAL=' + list.length)
