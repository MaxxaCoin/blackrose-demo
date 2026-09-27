// Live driver: exercises learn_folder against the REAL BlackRose source tree,
// then asks a question that can only be answered from the bulk-ingested files.
import fs from 'node:fs'
import { learnFolderTool, knowledgeSearchTool, knowledgeListTool } from 'file:///C:/Users/pc/Desktop/BlackRose/cline/blackrose/src/tools/knowledge.ts'

const base = 'C:/Users/pc/Desktop/BlackRose/validation/scratch-folder'
const dataDir = base + '/state'
fs.rmSync(dataDir, { recursive: true, force: true })
const ctx = { cwd: base, dataDir, askApproval: async () => true, log: () => {} }

const target = 'C:/Users/pc/Desktop/BlackRose/cline/blackrose/src'
const t0 = Date.now()
const res = await learnFolderTool.run({ path: target }, ctx)
const ms = Date.now() - t0
console.log('=== learn_folder on ' + target + ' ===')
console.log(res.content)
console.log('--- elapsed: ' + ms + ' ms')

console.log('=== knowledge_search: what does isTransientError do? ===')
console.log((await knowledgeSearchTool.run({ query: 'how are transient errors classified', k: 2 }, ctx)).content.slice(0, 500))

console.log('=== knowledge_list (first 3) ===')
console.log((await knowledgeListTool.run({}, ctx)).content.split('\n').slice(0, 3).join('\n'))
