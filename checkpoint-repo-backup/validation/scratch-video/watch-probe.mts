// Live driver for watch_video: real yt-dlp download + real cloud STT.
// Run: node validation/scratch-video/watch-probe.mts
import fs from 'node:fs'
import { watchVideoTool } from 'file:///C:/Users/pc/Desktop/BlackRose/cline/blackrose/src/tools/video.ts'

const scratch = 'C:/Users/pc/Desktop/BlackRose/validation/scratch-video'
const dataDir = scratch + '/state'
fs.rmSync(scratch + '/work', { recursive: true, force: true })
fs.mkdirSync(scratch + '/work', { recursive: true })
fs.mkdirSync(dataDir, { recursive: true })
// the STT key comes from User-scope env (BLACKROSE_OPENAI1_API_KEY) — inherited here

const ctx = { cwd: scratch + '/work', dataDir, askApproval: async () => true, log: (l) => console.log('  log:', l) }

const r = await watchVideoTool.run(
  { url: 'http://127.0.0.1:8123/test.wav', save: true, ingest: true },
  ctx,
)
console.log('--- result (isError:', r.isError === true, ') ---')
console.log(String(r.content).slice(0, 600))
console.log('--- sidecars ---')
const ups = scratch + '/work/blackrose-uploads'
console.log(fs.existsSync(ups) ? fs.readdirSync(ups).join(', ') : '(none)')
console.log('--- knowledge ---')
const kdir = dataDir + '/knowledge'
console.log(fs.existsSync(kdir) ? fs.readdirSync(kdir).filter((f) => f.endsWith('.json')).join(', ') : '(none)')
