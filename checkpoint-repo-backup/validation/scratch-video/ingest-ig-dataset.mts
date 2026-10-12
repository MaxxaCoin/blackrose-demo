// Transform the Apify Instagram-scraper dataset into clean per-post text
// (ranked by likes) and ingest it into the REAL BlackRose knowledge base.
// Run: node validation/scratch-video/ingest-ig-dataset.mts
import fs from 'node:fs'
import { learnFileTool, knowledgeSearchTool } from 'file:///C:/Users/pc/Desktop/BlackRose/cline/blackrose/src/tools/knowledge.ts'

const SRC = 'C:/Users/pc/Downloads/dataset_instagram-scraper_2026-09-28_07-14-22-309.json'
const OUT = 'C:/Users/pc/Desktop/BlackRose/validation/scratch-video/ig-reels-playbook.txt'
const dataDir = 'C:/Users/pc/.blackrose'

const posts: any[] = JSON.parse(fs.readFileSync(SRC, 'utf8'))
const ranked = posts
  .filter((p) => p.caption && p.caption.trim())
  .sort((a, b) => (b.likesCount ?? 0) - (a.likesCount ?? 0))

const lines: string[] = [
  'INSTAGRAM AI-REELS PLAYBOOK (petergriffin.ai) — scraped 2026-09-28.',
  `${ranked.length} reels, ranked by likes. Use this to learn what caption`,
  'styles, hashtag sets, and topics perform in the AI-tools niche.',
  '',
]
ranked.forEach((p, i) => {
  const dur = typeof p.videoDuration === 'number' ? Math.round(p.videoDuration) : null
  lines.push(`## #${i + 1} — ${(p.likesCount ?? 0).toLocaleString()} likes, ${(p.videoPlayCount ?? p.videoViewCount ?? 0).toLocaleString()} plays${dur ? `, ${dur}s` : ''} (${p.timestamp?.slice(0, 10) ?? 'undated'}, ${p.shortCode ?? ''})`)
  lines.push(`Hashtags: ${(p.hashtags || []).join(' ') || '(none)'}`)
  lines.push(`Caption: ${(p.caption || '').replace(/\s+\n/g, '\n').trim()}`)
  if (p.firstComment?.text) lines.push(`Pinned comment: ${String(p.firstComment.text).slice(0, 300)}`)
  lines.push('')
})

fs.writeFileSync(OUT, lines.join('\n'), 'utf8')
console.log('playbook written:', lines.length, 'lines,', ranked.length, 'posts')

const ctx = { cwd: dataDir, dataDir, askApproval: async () => true, log: (l: string) => console.log('  log:', l) }
const r = await learnFileTool.run({ path: OUT }, ctx)
console.log('learn_file ->', String(r.content).slice(0, 200))

for (const q of ['what captions perform best for AI reels', 'Claude Code plugins reels hashtags']) {
  const s = await knowledgeSearchTool.run({ query: q }, ctx)
  console.log('search [' + q + '] ->', String(s.content).split('\n').slice(0, 3).join(' | ').slice(0, 220))
}
