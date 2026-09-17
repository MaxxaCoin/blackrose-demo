// Dump full JSON for the "Free"-tagged KiraAI models + any with 'free' in id.
import fs from 'node:fs'
const base = process.env.KIRA_BASE_URL || 'https://kiraai.vn/api/v1'
let headers = {}
try { headers = { Authorization: 'Bearer ' + fs.readFileSync('C:/Users/pc/Documents/kira_api_key.txt', 'utf8').trim() } } catch { /* anonymous ok */ }
const r = await fetch(base + '/models', { headers })
const j = await r.json()
const list = Array.isArray(j?.data) ? j.data : []
const interesting = list.filter((m) => (typeof m.tags === 'string' && m.tags.toLowerCase().includes('free')) || (Array.isArray(m.tags) && m.tags.some((t) => String(t).toLowerCase().includes('free'))) || String(m.id).includes('free'))
for (const m of interesting) console.log(JSON.stringify(m))
console.log('INTERESTING=' + interesting.length)
