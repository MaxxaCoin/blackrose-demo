// Batch-watch the TOP N reels from the IG dataset: download via direct CDN
// URL, transcribe, ingest each transcript into the REAL knowledge base.
// Sequential on purpose (IG CDN + Groq rate limits). Failures are logged,
// never fatal. Run: node validation/scratch-video/batch-watch.mts
import fs from 'node:fs'
import { watchVideoTool } from 'file:///C:/Users/pc/Desktop/BlackRose/cline/blackrose/src/tools/video.ts'

const TOP = 15
const SRC = 'C:/Users/pc/Downloads/dataset_instagram-scraper_2026-09-28_07-14-22-309.json'
const dataDir = 'C:/Users/pc/.blackrose'
const work = 'C:/Users/pc/Desktop/BlackRose/validation/scratch-video/batch-work'
fs.mkdirSync(work, { recursive: true })

const posts: any[] = JSON.parse(fs.readFileSync(SRC, 'utf8'))
const top = posts
  .filter((p) => p.videoUrl && p.likesCount)
  .sort((a, b) => b.likesCount - a.likesCount)
  .slice(0, TOP)

const ctx = { cwd: work, dataDir, askApproval: async () => true, log: (l: string) => console.log('  log:', l) }
let ok = 0
let fail = 0
for (let i = 0; i < top.length; i++) {
  const p = top[i]
  const label = `#${i + 1} ${(p.likesCount ?? 0).toLocaleString()} likes ${p.shortCode ?? ''}`
  try {
    const r = await watchVideoTool.run({ url: p.videoUrl, save: true, ingest: true }, ctx)
    const good = r.isError !== true
    if (good) ok++
    else fail++
    console.log(`${good ? 'OK  ' : 'FAIL'} ${label} :: ${String(r.content).replace(/\s+/g, ' ').slice(0, 130)}`)
  } catch (e) {
    fail++
    console.log(`FAIL ${label} :: ${e instanceof Error ? e.message : String(e)}`)
  }
}
console.log(`DONE: ${ok} transcribed, ${fail} failed, of ${top.length}`)
