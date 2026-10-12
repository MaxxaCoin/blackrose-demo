// Exercise the REAL instagram_scrape code path against live Apify with a
// tiny result count, to prove the POST-with-input fix works end to end.
// The token is read from the attachment file and never echoed.
// Run: node validation/scratch-video/probe-instagram-live.mts
import fs from 'node:fs'

const TOKEN_FILE =
  'C:/Users/pc/.cline/data/sessions/session_1790588551324_d78af/user-attachments/35f10fd8-d5f0-46b3-9ccf-d72375f0e554-apify_api_key.txt'
process.env.APIFY_TOKEN = fs.readFileSync(TOKEN_FILE, 'utf8').trim()
console.log('APIFY_TOKEN set from file (not printed)')

const { instagramScrapeTool, instagramLearnTool } = await import(
  'file:///C:/Users/pc/Desktop/BlackRose/cline/blackrose/src/tools/instagram.ts'
)

const dataDir = 'C:/Users/pc/.blackrose'
const ctx = {
  cwd: 'C:/Users/pc/Desktop/BlackRose',
  dataDir,
  askApproval: async (name: string, reason: string) => {
    console.log('APPROVAL:', name, '->', reason)
    return true
  },
  log: (l: string) => console.log('  log:', l),
}

// results: 2 keeps the credit cost minimal; the point is to prove the run
// actually RECEIVES the URLs (the 0.9.2 bug returned an empty dataset).
const target = 'https://www.instagram.com/petergriffin.ai/'
const t0 = Date.now()
const r = await instagramScrapeTool.run({ targets: target, results: 2 }, ctx)
console.log('--- scrape finished in', Math.round((Date.now() - t0) / 1000), 's ---')
const out = String(r.content)
console.log('isError:', r.isError === true)
console.log('content head:\n' + out.slice(0, 900))

if (!r.isError && out.includes('## #')) {
  console.log('\nSUCCESS: the playbook has post headings, so the actor received the URL.')
  const learned = await instagramLearnTool.run(
    { path: dataDir + '/instagram-playbook.md' },
    ctx,
  )
  console.log('learn ->', String(learned.content).slice(0, 200))
} else {
  console.log('\nFAILED: no posts came back. The run did not receive the URLs.')
}
