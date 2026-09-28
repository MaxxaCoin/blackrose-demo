// One-shot driver: ingest the Tech God master curriculum into the REAL
// BlackRose data dir (~/.blackrose) so the installed app can search it.
// Run: node validation/scratch-curriculum/ingest-curriculum.mts
import fs from 'node:fs'
import { learnFileTool } from 'file:///C:/Users/pc/Desktop/BlackRose/cline/blackrose/src/tools/knowledge.ts'

const dataDir = 'C:/Users/pc/.blackrose'
const staging = 'C:/Users/pc/Desktop/BlackRose/validation/scratch-curriculum/staging'
fs.mkdirSync(staging, { recursive: true })

const src = 'C:/Users/pc/Downloads/blackrose.txt'
const dest = staging + '/tech-god-master-curriculum.txt'
fs.copyFileSync(src, dest)

const ctx = { cwd: 'C:/Users/pc/Desktop/BlackRose', dataDir, askApproval: async () => true, log: (l) => console.log('  log:', l) }
const r = await learnFileTool.run({ path: dest }, ctx)
console.log('learn_file ->', r.content)

// verify it is searchable
const { knowledgeSearchTool } = await import('file:///C:/Users/pc/Desktop/BlackRose/cline/blackrose/src/tools/knowledge.ts')
const s = await knowledgeSearchTool.run({ query: 'quantum computing qubits curriculum' }, ctx)
console.log('knowledge_search ->', (s.content || '').slice(0, 220))
const s2 = await knowledgeSearchTool.run({ query: 'cybersecurity CIA triad' }, ctx)
console.log('knowledge_search ->', (s2.content || '').slice(0, 220))
