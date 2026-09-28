// Ingest BlackRose's own design-history chat log into the REAL knowledge base.
// Run: node validation/scratch-video/ingest-design-history.mts
import fs from 'node:fs'
import { learnFileTool, knowledgeSearchTool } from 'file:///C:/Users/pc/Desktop/BlackRose/cline/blackrose/src/tools/knowledge.ts'

const SRC = 'C:/Users/pc/Music/br ai ass/BlackRose.txt'
const OUT = 'C:/Users/pc/Desktop/BlackRose/validation/scratch-video/design-history.txt'
const dataDir = 'C:/Users/pc/.blackrose'

const raw = fs.readFileSync(SRC, 'utf8')
fs.writeFileSync(OUT, `BLACKROSE PROJECT DESIGN HISTORY — past chat log (2026-09), preserved for institutional memory.\n\n${raw}`, 'utf8')
console.log('staged:', (raw.length / 1024).toFixed(0) + 'KB')

const ctx = { cwd: dataDir, dataDir, askApproval: async () => true, log: (l: string) => console.log('  log:', l) }
const r = await learnFileTool.run({ path: OUT }, ctx)
console.log('learn_file ->', String(r.content).slice(0, 160))

const s = await knowledgeSearchTool.run({ query: 'why BlackRose UI sidebar design decisions' }, ctx)
console.log('search ->', String(s.content).split('\n').slice(0, 3).join(' | ').slice(0, 200))
