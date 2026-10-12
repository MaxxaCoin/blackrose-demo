/**
 * Live 1min.ai agent probe — runs the REAL agent loop (tools + approvals +
 * tool_result feedback) against 1min.ai only (no fallback), to prove the
 * text tool protocol survives a full write→read roundtrip on disk.
 *
 * Run: node validation/scratch-onemin/onemin-agent-probe.mjs
 * Requires: BLACKROSE_ONEMIN_API_KEY in env (persisted user env).
 */
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { runAgent } from '../../cline/blackrose/src/core/agent.ts'
import { oneMinClient } from '../../cline/blackrose/src/llm/onemin.ts'
import { buildTools } from '../../cline/blackrose/src/tools/index.ts'

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'onemin-probe-'))
const target = path.join(dir, 'onemin-e2e.txt')
const client = oneMinClient({
  apiKey: process.env.BLACKROSE_ONEMIN_API_KEY,
  model: process.env.BLACKROSE_ONEMIN_MODEL || 'gpt-4o-mini',
})

const outcome = await runAgent({
  client,
  tools: buildTools(),
  system: 'You are BlackRose. Use tools to finish tasks. Be brief.',
  history: [
    {
      role: 'user',
      content:
        'Create the file onemin-e2e.txt in the current directory with the exact content "hello from 1min" using write_file. Then read it back with read_file and tell me what it says.',
    },
  ],
  ctx: {
    cwd: dir,
    dataDir: dir,
    askApproval: async (tool, reason) => {
      console.log(`  [approval] ${tool}: ${reason} → auto-allow (probe)`)
      return true
    },
    log: () => {},
  },
  maxTurns: 8,
  onToolCall: (name, input) => console.log(`  [tool] ${name} ${JSON.stringify(input).slice(0, 120)}`),
  onToolResult: (name, r) => console.log(`  [result] ${name}${r.isError ? ' ERROR' : ''}: ${r.content.slice(0, 80)}`),
})

console.log(`\nturns=${outcome.turns}`)
console.log(`final: ${outcome.text.slice(0, 300)}`)
const onDisk = fs.existsSync(target) ? fs.readFileSync(target, 'utf8') : '(missing)'
console.log(`file on disk: ${onDisk}`)
console.log(fs.existsSync(target) && onDisk.includes('1min') ? 'PASS' : 'FAIL')
fs.rmSync(dir, { recursive: true, force: true })
