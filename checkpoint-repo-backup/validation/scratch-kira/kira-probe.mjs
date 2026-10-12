// Live KiraAI validation probe — reads the API key from file, NEVER prints it.
// Checks: /models with Bearer, plain chat completion, native tool_calls,
// and text-JSON tool-call recovery (the failure mode BlackRose recovers from).
import fs from 'node:fs'

const KEY_FILE = 'C:/Users/pc/Documents/kira_api_key.txt'
const base = process.env.KIRA_BASE_URL || 'https://kiraai.vn/api/v1'
const model = process.env.KIRA_MODEL || 'deepseek-v4-flash-free'
const key = fs.readFileSync(KEY_FILE, 'utf8').trim()
if (!key) { console.log('[FAIL] key file empty'); process.exit(1) }
const auth = { Authorization: 'Bearer ' + key, 'Content-Type': 'application/json' }
const timeout = (ms) => {
  const ac = new AbortController()
  const t = setTimeout(() => ac.abort(), ms)
  return [ac.signal, () => clearTimeout(t)]
}
function tag(name, ok, extra = '') {
  console.log(`[${ok ? 'OK' : 'FAIL'}] ${name}${extra ? ' :: ' + extra : ''}`)
}

// 1) models list with Bearer auth
{
  const [sig, done] = timeout(30_000)
  try {
    const r = await fetch(base + '/models', { headers: { Authorization: 'Bearer ' + key }, signal: sig })
    const j = await r.json()
    const list = Array.isArray(j?.data) ? j.data : []
    const free = list.filter((m) => m.is_free === true && (m.status ?? 'active') === 'active')
    const ours = list.find((m) => m.id === model)
    tag('models', r.ok && list.length > 0, `${list.length} models, ${free.length} free-active, target=${model} ${ours ? 'PRESENT' : 'MISSING'}`)
  } catch (e) {
    tag('models', false, String(e?.message || e).slice(0, 160))
  } finally { done() }
}

// 2) plain chat completion
{
  const [sig, done] = timeout(90_000)
  try {
    const r = await fetch(base + '/chat/completions', {
      method: 'POST', headers: auth, signal: sig,
      body: JSON.stringify({ model, messages: [{ role: 'user', content: 'Reply with exactly KIRA_OK and nothing else.' }], max_tokens: 50 }),
    })
    const j = await r.json()
    const text = j?.choices?.[0]?.message?.content ?? ''
    const err = j?.error
    tag('chat', r.ok && !err && String(text).includes('KIRA_OK'), err ? JSON.stringify(err).slice(0, 160) : JSON.stringify(text).slice(0, 120))
  } catch (e) {
    tag('chat', false, String(e?.message || e).slice(0, 160))
  } finally { done() }
}

// 3) native tool_calls roundtrip
{
  const [sig, done] = timeout(90_000)
  try {
    const r = await fetch(base + '/chat/completions', {
      method: 'POST', headers: auth, signal: sig,
      body: JSON.stringify({
        model,
        messages: [{ role: 'user', content: 'What is the weather in Paris right now? Use the tool.' }],
        tools: [{ type: 'function', function: { name: 'get_weather', description: 'Get current weather for a city', parameters: { type: 'object', properties: { city: { type: 'string' } }, required: ['city'] } } }],
        tool_choice: 'auto',
        max_tokens: 200,
      }),
    })
    const j = await r.json()
    const msg = j?.choices?.[0]?.message
    const calls = msg?.tool_calls ?? []
    const fn = calls[0]?.function?.name
    const err = j?.error
    if (fn) {
      let args = {}
      try { args = JSON.parse(calls[0].function.arguments || '{}') } catch { /* recovered below */ }
      tag('tool_calls', fn === 'get_weather' && args.city, `native call ${fn}(${JSON.stringify(args).slice(0, 80)})`)
    } else {
      const text = typeof msg?.content === 'string' ? msg.content : ''
      const recovered = text.includes('"name"') && text.includes('get_weather')
      tag('tool_calls', recovered, err ? 'ERROR ' + JSON.stringify(err).slice(0, 140) : recovered ? 'no native calls but text-JSON recoverable' : 'no calls, content: ' + JSON.stringify(text).slice(0, 120))
    }
  } catch (e) {
    tag('tool_calls', false, String(e?.message || e).slice(0, 160))
  } finally { done() }
}
console.log('KIRA_PROBE_DONE')
