// Live clear-conversation probe: reproduce the user's scenario end-to-end
// against a running BlackRose web UI server.
//   1. GET / must send cache-control: no-store
//   2. codeword → remembered across turns
//   3. 🧹 (/api/new) → codeword must be forgotten
//   4. a brand-new tab (fresh key) must not resurrect it either
const base = process.argv[2] ?? 'http://localhost:8791'
const S = 'probe-' + Math.random().toString(36).slice(2, 8)

const page = await fetch(base + '/')
console.log('cache-control:', page.headers.get('cache-control'))

async function ask(prompt, session) {
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
    } catch {}
  }
  return final
}

const set = await ask('Remember this codeword: MOONLITROSE. Reply with just: OK', S)
console.log('turn1 (set):', set.slice(0, 80))
const got = await ask('What codeword did I give you? Reply with just the codeword.', S)
console.log('turn2 (recall):', got.slice(0, 80))

await fetch(base + '/api/new', {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ session: S }),
})
const afterClear = await ask('What codeword did I give you earlier? If none, reply NONE.', S)
console.log('turn3 (after clear):', afterClear.slice(0, 80))
const freshTab = await ask('What codeword did I give you earlier? If none, reply NONE.', 'fresh-' + S)
console.log('turn4 (fresh tab):', freshTab.slice(0, 80))

const noStore = (page.headers.get('cache-control') ?? '').includes('no-store')
const pass =
  noStore &&
  got.includes('MOONLITROSE') &&
  !afterClear.includes('MOONLITROSE') &&
  !freshTab.includes('MOONLITROSE')
console.log(pass ? 'UI-CLEAR PASS' : 'UI-CLEAR FAIL')
