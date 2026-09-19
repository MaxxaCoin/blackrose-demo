// Live probe for the LOCAL push-to-talk engine (backlog 3-STT), no mic needed:
//   1. SAPI TTS writes a sentinel WAV
//   2. the SHIPPING tool (buildTools() → listen) transcribes that WAV with the
//      local Windows dictation engine — fully offline
//   3. the transcript must contain recognizable sentinel words
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { execFileSync } from 'node:child_process'
import { buildTools } from '../../cline/blackrose/src/tools/index.ts'

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'blackrose-listen-'))
const wav = path.join(dir, 'listen-sentinel.wav')
const phrase = 'Black Rose local speech sentinel. The quick brown fox jumps over the lazy dog.'

// 1. synthesize the sentinel (SAPI TTS, offline)
const ps = [
  'Add-Type -AssemblyName System.Speech',
  '$s=New-Object System.Speech.Synthesis.SpeechSynthesizer',
  `$s.SetOutputToWaveFile('${wav.replace(/'/g, "''")}')`,
  `$s.Speak('${phrase.replace(/'/g, "''")}')`,
  '$s.Dispose()',
].join('; ')
execFileSync('powershell', ['-NoProfile', '-Command', ps], { stdio: 'inherit' })
console.log('sentinel wav:', wav, fs.statSync(wav).size, 'bytes')

// 2. run the real tool in offline WAV mode
const listen = buildTools().find((t) => t.name === 'listen')
if (!listen) throw new Error('listen tool is not registered')
const res = await listen.run({ path: wav }, { cwd: dir, dataDir: dir })
console.log('\ntool result (isError=%s):\n%s', res.isError === true, res.content)

// 3. verdict
const text = String(res.content).toLowerCase()
const hits = ['black', 'rose', 'sentinel', 'fox', 'lazy dog'].filter((w) => text.includes(w))
console.log('\nsentinel words recognized:', hits.join(', ') || '(none)')
console.log(res.isError !== true && hits.length >= 2 ? 'LOCAL-STT PASS' : 'LOCAL-STT FAIL')