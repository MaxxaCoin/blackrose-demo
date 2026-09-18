// Live STT probe (backlog item 2): synthesize a sentinel WAV with Windows SAPI,
// then run the SHIPPING transcribe_audio tool (src/tools/stt.ts) against the
// real Groq endpoint. The sentinel phrase must roundtrip; sidecar + knowledge
// ingest are exercised too. Run: node validation/scratch-openrouter/stt-probe.ts
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { execSync } from 'node:child_process'
import { transcribeAudioTool } from '../../cline/blackrose/src/tools/stt.ts'
import { knowledgeSearchTool } from '../../cline/blackrose/src/tools/knowledge.ts'

// Key: env first, else the Documents key file (loaded in-process, never printed)
if (!process.env.BLACKROSE_STT_API_KEY && !process.env.BLACKROSE_OPENAI1_API_KEY) {
  process.env.BLACKROSE_STT_API_KEY = fs
    .readFileSync('C:/Users/pc/Documents/groq_api_key.txt', 'utf8')
    .trim()
}

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'blackrose-stt-'))
const wav = path.join(dir, 'sentinel.wav')
const ps = [
  'Add-Type -AssemblyName System.Speech',
  '$s=New-Object System.Speech.Synthesis.SpeechSynthesizer',
  "$s.SetOutputToWaveFile('" + wav.replace(/\\/g, '/') + "')",
  "$s.Speak('BlackRose speech to text sentinel. The quick brown fox jumps over the lazy dog.')",
  '$s.Dispose()',
].join('; ')
execSync('powershell -NoProfile -Command "' + ps + '"', { timeout: 30_000 })
const stat = fs.statSync(wav)
console.log('sentinel wav:', (stat.size / 1024).toFixed(0), 'KB')

const ctx = {
  cwd: dir,
  dataDir: dir,
  askApproval: async () => true,
  log: (l) => console.log('  log:', l),
}
const r = await transcribeAudioTool.run({ path: wav, save: true, ingest: true }, ctx)
console.log('--- tool output ---')
console.log(r.content)
const sidecar = wav.replace(/\.wav$/, '') + '.transcript.txt'
const search = await knowledgeSearchTool.run({ query: 'quick brown fox' }, ctx)
console.log('--- knowledge_search ---')
console.log(search.content.slice(0, 200))
const text = r.content.toLowerCase()
const ok =
  !r.isError &&
  text.includes('quick brown fox') &&
  text.includes('lazy dog') &&
  fs.existsSync(sidecar) &&
  search.content.toLowerCase().includes('fox')
console.log(ok ? 'STT PROBE PASS' : 'STT PROBE FAIL')
