// Live UI context-memory probe: two /api/ask turns against a running
// BlackRose web UI server. Turn 2 must recall turn 1's codeword.
const base = process.argv[2] ?? 'http://localhost:8790'
const session = 'probe-' + Math.random().toString(36).slice(2, 8)

async function ask(prompt) {
  const res = await fetch(base + '/api/ask', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ prompt, session }),
  })
  let final = ''
  for (const line of (await res.text()).split('\n')) {
    if (!line.trim()) continue
    try {
      const ev = JSON.parse(line)
      if (ev.type === 'final') final = ev.text ?? ''
      if (ev.type === 'error') final = 'ERROR: ' + (ev.text ?? '')
    } catch {
      /* ignore partial lines */
    }
  }
  return final
}

const health = await fetch(base + '/api/health').then((r) => r.json())
console.log('server:', health.provider, '·', health.model)

const a = await ask('Remember this codeword: CRIMSONFALCON. Reply with just: OK')
console.log('turn1:', a.slice(0, 120))
const b = await ask('What codeword did I give you? Reply with just the codeword.')
console.log('turn2:', b.slice(0, 120))
console.log(b.includes('CRIMSONFALCON') ? 'UI-CONTEXT PASS' : 'UI-CONTEXT FAIL')
