// Ingest the ChatGPT-designed learning program for BlackRose (Phases 0-3:
// learning core, computer systems, Python, software engineering) into the
// REAL knowledge base as the mission roadmap.
// Run: node validation/scratch-video/ingest-learning-program.mts
import fs from 'node:fs'
import { learnFileTool, knowledgeSearchTool } from 'file:///C:/Users/pc/Desktop/BlackRose/cline/blackrose/src/tools/knowledge.ts'

const SRC = 'C:/Users/pc/Documents/chatgpt_response.txt'
const OUT = 'C:/Users/pc/Desktop/BlackRose/validation/scratch-video/learning-program.txt'
const dataDir = 'C:/Users/pc/.blackrose'

const raw = fs.readFileSync(SRC, 'utf8')
fs.writeFileSync(
  OUT,
  `BLACKROSE LEARNING PROGRAM (mission roadmap, designed 2026-09-28).\n` +
  `Order: Phase 0 learning core (reasoning, research, tools/plugins/skills,\n` +
  `tool discovery) → Phase 1 computer systems (hardware, CPU, OS, Windows,\n` +
  `Linux, virtualization) → Phase 2 Python mastery → Phase 3 software\n` +
  `engineering + Git/GitHub → then networking, databases, web, cloud,\n` +
  `security, AI/ML, agents, automation. Learning method per topic:\n` +
  `LEARN → RESEARCH → EXPLAIN → PRACTICE → USE A TOOL → EXPERIMENT →\n` +
  `VERIFY → CREATE SKILL → RECORD EXPERIENCE → TEST AGAIN. Every subject\n` +
  `in four dimensions: knowledge, skills, tools, experience. Never claim\n` +
  `knowledge or success without evidence; track uncertainty explicitly.\n\n` +
  raw,
  'utf8',
)
console.log('staged:', (raw.length / 1024).toFixed(0) + 'KB')

const ctx = { cwd: dataDir, dataDir, askApproval: async () => true, log: (l: string) => console.log('  log:', l) }
const r = await learnFileTool.run({ path: OUT }, ctx)
console.log('learn_file ->', String(r.content).slice(0, 160))

for (const q of ['what is BlackRose first learning mission phase 0', 'how should BlackRose learn each topic method']) {
  const s = await knowledgeSearchTool.run({ query: q }, ctx)
  console.log('search [' + q.slice(0, 30) + '…] ->', String(s.content).split('\n')[0].slice(0, 140))
}
