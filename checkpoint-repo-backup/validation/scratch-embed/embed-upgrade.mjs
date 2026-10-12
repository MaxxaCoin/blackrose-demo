// Embedding-model upgrade validation (item ④): proves, against the live local
// Ollama, that BlackRose retrieval (1) still works on the pure-hash fallback,
// (2) upgrades to real nomic-embed-text vectors and re-indexes cleanly, and
// (3) fails safe (falls back) when the configured model cannot embed.
// Run: node validation\scratch-embed\embed-upgrade.mjs
import fs from 'node:fs'
import path from 'node:path'
import { pathToFileURL } from 'node:url'

const ROOT = 'C:/Users/pc/Desktop/BlackRose/cline/blackrose/src'
const { saveKnowledge } = await import(pathToFileURL(`${ROOT}/tools/knowledge.ts`).href)
const { hybridRank, openStore } = await import(pathToFileURL(`${ROOT}/memory/hybrid.ts`).href)
const { resetEmbedProbe } = await import(pathToFileURL(`${ROOT}/memory/embedder.ts`).href)

const dir = 'C:/Users/pc/Desktop/BlackRose/validation/scratch-validation/embed-probe'
const results = []
const ok = (name, cond, detail) => {
  results.push({ name, pass: Boolean(cond), detail })
  console.log(`${cond ? 'PASS' : 'FAIL'} — ${name} :: ${detail}`)
}

// Three separate sources → exactly three chunks with stable ids.
const SOURCES = [
  { slug: 'pancake-recipe', text: 'Banana pancake recipe: mash two ripe bananas, whisk with two eggs, fry thin circles in butter, flip once, serve with syrup and berries.' },
  { slug: 'telemetry-runbook', text: 'Ops runbook for the telemetry service: to publish an update, tag the repo, build the installer, upload it to the share, then verify the pipeline finished green before announcing the rollout to the team.' },
  { slug: 'garden-notes', text: 'Weather notes: the garden needs deep watering twice a week during heat waves, and tomatoes should be harvested before the first frost.' },
]
const RUNBOOK = 'kb:telemetry-runbook#chunk1'

async function freshDir() {
  fs.rmSync(dir, { recursive: true, force: true })
  fs.mkdirSync(dir, { recursive: true })
}

async function learnAll() {
  for (const s of SOURCES) await saveKnowledge(dir, s.slug, 'file', s.text)
}

async function rankQuery(label, query, expectFirstId) {
  const files = fs.readdirSync(path.join(dir, 'knowledge'))
  const entries = []
  for (const f of files.filter((x) => x.endsWith('.json'))) {
    const kf = JSON.parse(fs.readFileSync(path.join(dir, 'knowledge', f), 'utf8'))
    const base = f.replace(/\.json$/, '')
    kf.chunks.forEach((c, i) => entries.push({ id: `kb:${base}#chunk${i + 1}`, text: c, mtime: Date.parse(kf.saved) }))
  }
  const store = openStore(dir)
  const ranked = await hybridRank(query, entries, store, 'kb:', 3)
  ok(
    `${label}: expected top hit`,
    entries.length === 3 && ranked[0]?.id === expectFirstId,
    `query="${query}" top=${ranked[0]?.id} score=${ranked[0]?.score?.toFixed(2)} all=[${ranked.map((r) => `${r.id}:${r.score.toFixed(2)}`).join(', ')}]`,
  )
  return { store, ranked }
}

// ---- Probe A: hash fallback (BLACKROSE_EMBED=off) ----
await freshDir()
process.env.BLACKROSE_EMBED = 'off'
resetEmbedProbe()
await learnAll()
{
  const { store } = await rankQuery('A fallback', 'steps to publish the update', RUNBOOK)
  ok('A fallback: hash backend identity', store.file.model === 'br-hash-v1' && store.file.dim === 256,
    `model=${store.file.model} dim=${store.file.dim}`)
  ok('A fallback: vector file written', fs.existsSync(path.join(dir, 'vectors', 'index.json')),
    path.join(dir, 'vectors', 'index.json'))
}

// ---- Probe B: real model (nomic-embed-text) ----
await freshDir()
delete process.env.BLACKROSE_EMBED
resetEmbedProbe()
await learnAll()
{
  const { store } = await rankQuery('B real-model', 'steps to publish the update', RUNBOOK)
  ok('B real-model: nomic-embed-text backend', store.file.model === 'nomic-embed-text' && store.file.dim === 768,
    `model=${store.file.model} dim=${store.file.dim}`)
  ok('B real-model: vector file written', fs.existsSync(path.join(dir, 'vectors', 'index.json')),
    path.join(dir, 'vectors', 'index.json'))
  // Semantic evidence: a query with NO word overlap with the runbook text.
  const { ranked } = await rankQuery('B semantic (no keyword overlap)', 'how do I ship a new version to the team?', RUNBOOK)
  ok('B semantic: runbook beats unrelated chunks', ranked.length >= 2 && ranked[ranked.length - 1]?.id !== RUNBOOK,
    `ranking=[${ranked.map((r) => r.id).join(', ')}]`)
}

// ---- Probe C: wrong model type fails safe ----
await freshDir()
process.env.BLACKROSE_EMBED_MODEL = 'qwen2.5-coder:7b' // a chat model, not an embedder
resetEmbedProbe()
await learnAll()
{
  const { store } = await rankQuery('C fail-safe', 'steps to publish the update', RUNBOOK)
  ok('C fail-safe: fell back to hash backend', store.file.model === 'br-hash-v1' && store.file.dim === 256,
    `model=${store.file.model} dim=${store.file.dim} (configured qwen2.5-coder:7b could not embed)`)
}
delete process.env.BLACKROSE_EMBED_MODEL

const failed = results.filter((r) => !r.pass)
console.log(failed.length === 0 ? 'EMBED UPGRADE VALIDATION PASSED' : `EMBED UPGRADE VALIDATION FAILED (${failed.length})`)
process.exit(failed.length === 0 ? 0 : 1)
