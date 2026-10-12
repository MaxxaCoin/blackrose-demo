// Offline check of the Instagram tools: no APIFY_TOKEN -> the scrape must
// fail closed with setup instructions, and instagram_learn must ingest a
// real playbook built from the actual Apify dataset already on disk.
// Run: node validation/scratch-video/probe-instagram-tools.mts
import fs from 'node:fs'
import {
  instagramScrapeTool,
  instagramLearnTool,
} from 'file:///C:/Users/pc/Desktop/BlackRose/cline/blackrose/src/tools/instagram.ts'

const dataDir = 'C:/Users/pc/.blackrose'
const ctx = {
  cwd: 'C:/Users/pc/Desktop/BlackRose',
  dataDir,
  askApproval: async () => { console.log('  (approval asked -> auto-yes)'); return true },
  log: (l: string) => console.log('  log:', l),
}

// 1. fail closed with no token
delete process.env.APIFY_TOKEN
const noTok = await instagramScrapeTool.run({ targets: 'https://www.instagram.com/petergriffin.ai/' }, ctx)
console.log('scrape w/o token ->', String(noTok.content).slice(0, 120), '| isError:', noTok.isError === true)

// 2. a real playbook built from the real Apify dataset -> learn it
const SRC = 'C:/Users/pc/Downloads/dataset_instagram-scraper_2026-09-28_07-14-22-309.json'
if (fs.existsSync(SRC)) {
  const posts = JSON.parse(fs.readFileSync(SRC, 'utf8'))
  const ranked = posts.filter((p: any) => p.caption && p.caption.trim())
    .sort((a: any, b: any) => (b.likesCount ?? 0) - (a.likesCount ?? 0))
  const md = [
    'INSTAGRAM PLAYBOOK (probe) — built from the real Apify dataset.',
    `${ranked.length} posts ranked by likes.`, '',
    ...ranked.slice(0, 12).flatMap((p: any, i: number) => [
      `## #${i + 1} — ${(p.likesCount ?? 0).toLocaleString()} likes (@${p.ownerUsername})`,
      `Hashtags: ${(p.hashtags || []).join(' ') || '(none)'}`,
      `Caption: ${String(p.caption).slice(0, 300)}`, '',
    ]),
  ].join('\n')

  const noConfirm = await instagramLearnTool.run({ markdown: md }, ctx)
  console.log('learn w/o confirm ->', String(noConfirm.content).slice(0, 90))

  const r = await instagramLearnTool.run({ markdown: md, confirm: true }, ctx)
  console.log('learn w/ confirm ->', String(r.content).slice(0, 160), '| isError:', r.isError === true)

  const { knowledgeSearchTool } = await import('file:///C:/Users/pc/Desktop/BlackRose/cline/blackrose/src/tools/knowledge.ts')
  const s = await knowledgeSearchTool.run({ query: 'Instagram caption styles that perform' }, ctx)
  console.log('search ->', String(s.content).slice(0, 200))
} else {
  console.log('dataset not found, skipped the learn half of the probe')
}
