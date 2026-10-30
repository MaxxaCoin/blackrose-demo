"""Build the 20-pair retrieval eval gate.

1. knowledge.ts: lift the canonical corpus + queries into exported constants
   (RETRIEVAL_EVAL_DOCS / RETRIEVAL_EVAL_QUERIES), 12 docs + 20 pairs, and make
   knowledge_eval consume them. Also drop the dead duplicated lines after the
   tool's return.
2. New src/tools/retrieval-eval.test.ts: the blocking gate - 20/20, hermetic
   (BLACKROSE_EMBED=off, no key, no network).
3. Register it in npm test.
"""
import sys

K = r'C:\Users\pc\Desktop\BlackRose\cline\blackrose\src\tools\knowledge.ts'
c = open(K, 'rb').read().decode('utf-8').replace('\r\n', '\n')

# 1. replace the inline corpus + queries with module-level constants
OLD_HEAD = "export const knowledgeEvalTool = buildTool({"
assert c.count(OLD_HEAD) == 1

CONSTS = '''/**
 * The retrieval eval corpus - one fixed, human-written set of documents and
 * question→expected-source pairs. Exported so the blocking gate
 * (retrieval-eval.test.ts) can assert the SIZE (12 docs / 20 pairs) instead of
 * trusting a comment, and so nobody can quietly shrink the gate.
 *
 * Why this matters: every chunking/embedding/ranking change ships unmeasured
 * without it, and a large corpus can silently make answers worse. The gate must
 * be green BEFORE any bulk ingest.
 */
export const RETRIEVAL_EVAL_DOCS: { source: string; text: string; verified?: boolean; agent?: string; confidence?: number }[] = [
  {
    source: 'deploy-checklist',
    text:
      'Deployment checklist: run the tests, bump the version, build the installer, sign it with the release key, upload the assets, then re-download and re-hash every file before announcing the tag.',
    verified: true,
    agent: 'system',
    confidence: 0.95,
  },
  {
    source: 'incident-postmortem',
    text:
      'Incident postmortem: a cache stampede on 2026-09-12 caused elevated latency; the root cause was a missing lock around the refresh, and the fix added single-flight so only one request rebuilds the entry.',
    verified: false,
    agent: 'agent',
    confidence: 0.6,
  },
  {
    source: 'onboarding-guide',
    text:
      'Onboarding guide: clone the repository, install the dependencies, start the dev server, read the project constitution, and ask questions in the team channel before opening a pull request.',
    verified: true,
    agent: 'user',
    confidence: 0.85,
  },
  {
    source: 'telegram-companion',
    text:
      'Telegram companion: store the BotFather token, bind the owner chat, then the phone can drive the agent. Tool calls that need consent show Allow and Deny buttons; trust mode skips the prompt until it is turned off again.',
    verified: true,
    agent: 'user',
    confidence: 0.9,
  },
  {
    source: 'knowledge-ingestion',
    text:
      'Knowledge ingestion: every item is hashed with sha256 so re-ingesting identical content only refreshes metadata. Records carry front matter with source, agent, confidence, verified and a summary, and retrieval cites that provenance.',
    verified: true,
    agent: 'system',
    confidence: 0.9,
  },
  {
    source: 'vector-index',
    text:
      'Vector index: embeddings come from the configured model at 3072 dimensions, with a hashed subword fallback at 256 dimensions when the API is unavailable. Ranking prunes the store to the documents it is given, so never call it with a partial list or the other vectors are deleted.',
    verified: false,
    agent: 'agent',
    confidence: 0.7,
  },
  {
    source: 'undo-journal',
    text:
      'Undo journal: every file-changing tool snapshots the exact bytes before it writes, records the entry in the journal, and the undo tool restores that snapshot; restoring is itself journalled so it can be redone by id.',
    verified: true,
    agent: 'system',
    confidence: 0.9,
  },
  {
    source: 'budget-caps',
    text:
      'Spend caps: a ledger records tokens for every model call and billed generations, and one active cap limits tokens or billed calls per day, month or all time. The check refuses at the spend point before the network call is made.',
    verified: true,
    agent: 'system',
    confidence: 0.9,
  },
  {
    source: 'mcp-servers',
    text:
      'MCP servers: an external tool server speaks JSON-RPC over stdio. It is untrusted by default and every call asks for approval unless the server is marked trusted in its configuration; boot-loaded children can be killed by the emergency stop.',
    verified: true,
    agent: 'system',
    confidence: 0.85,
  },
  {
    source: 'backup-rotation',
    text:
      'Backup rotation: an encrypted snapshot of the state directory is written every hour, the newest fourteen are kept, and restoring one requires the state password because the archive is sealed with AES-GCM.',
    verified: true,
    agent: 'system',
    confidence: 0.9,
  },
  {
    source: 'skills-and-macros',
    text:
      'Skills and macros: a skill is a markdown recipe with front matter that a sub-agent can run, and teach-by-demonstration records the tool calls you perform, then saves the recording as an ordinary skill you can review and edit.',
    verified: true,
    agent: 'user',
    confidence: 0.85,
  },
  {
    source: 'security-policy',
    text:
      'Security policy: rules can allow, deny or force approval per tool, optionally scoped to a path. The strictest matching rule wins, and a path-scoped rule also applies to shell commands whose target cannot be proven to be out of scope.',
    verified: true,
    agent: 'system',
    confidence: 0.9,
  },
]

/** The 20 fixed question→expected-source pairs the gate scores. */
export const RETRIEVAL_EVAL_QUERIES: { q: string; expect: string }[] = [
  { q: 'how do I cut a release and sign the installer', expect: 'deploy-checklist' },
  { q: 'which steps deploy to production', expect: 'deploy-checklist' },
  { q: 'what caused the cache stampede latency', expect: 'incident-postmortem' },
  { q: 'single flight lock fix for the stampede', expect: 'incident-postmortem' },
  { q: 'first day setup clone repo install dependencies', expect: 'onboarding-guide' },
  { q: 'where do I read the project constitution', expect: 'onboarding-guide' },
  { q: 'bind a telegram bot token to the companion', expect: 'telegram-companion' },
  { q: 'how does the owner approve a tool on the phone', expect: 'telegram-companion' },
  { q: 'how does knowledge ingestion stay idempotent', expect: 'knowledge-ingestion' },
  { q: 'what front matter does an ingested item carry', expect: 'knowledge-ingestion' },
  { q: 'why was the vector index pruned', expect: 'vector-index' },
  { q: 'embedding fallback to the hash embedder', expect: 'vector-index' },
  { q: 'how do I undo a file change from a tool', expect: 'undo-journal' },
  { q: 'snapshot the bytes before writing a file', expect: 'undo-journal' },
  { q: 'set a spend cap for tokens per day', expect: 'budget-caps' },
  { q: 'where is usage recorded for each model call', expect: 'budget-caps' },
  { q: 'connect an MCP stdio server and trust it', expect: 'mcp-servers' },
  { q: 'restore state from an encrypted backup', expect: 'backup-rotation' },
  { q: 'turn a recorded demo into a reusable skill', expect: 'skills-and-macros' },
  { q: 'block a tool for a specific path with a deny rule', expect: 'security-policy' },
]

export const knowledgeEvalTool = buildTool({'''

c = c.replace(OLD_HEAD, CONSTS, 1)

# 2. replace the inline cases/queries in the tool run with the constants
OLD_CASES_START = """      const cases: { source: string; text: string; verified?: boolean; agent?: string; confidence?: number }[] = [
        {
          source: 'deploy-checklist',"""
i = c.index(OLD_CASES_START)
j = c.index("      // Build entries the same way knowledge_search does.", i)
NEW_BODY = """      const cases = RETRIEVAL_EVAL_DOCS
      const queries = RETRIEVAL_EVAL_QUERIES
      const env = { dataDir: tmpDataDir, cwd: tmpDataDir }
      for (const c of cases) {
        await ingestItem(env, { kind: 'text', ...c })
      }
"""
c = c[:i] + NEW_BODY + c[j:]

# 3. drop the dead duplicated lines after the first return in the tool body
DEAD = """      lines.push('')
      lines.push(`result: ${passed}/${queries.length} passed${passed === queries.length ? '  ✓' : '  ✗'}`)
      return { content: lines.join('\\n') }
      lines.push('')
      lines.push(`result: ${passed}/${queries.length} passed${passed === queries.length ? '  ✓' : '  ✗'}`)
      return { content: lines.join('\\n') }"""
ALIVE = """      lines.push('')
      lines.push(`result: ${passed}/${queries.length} passed${passed === queries.length ? '  ✓' : '  ✗'}`)
      return { content: lines.join('\\n') }"""
n = c.count(DEAD)
if n == 1:
    c = c.replace(DEAD, ALIVE)
    print('ok dead duplicate removed')
else:
    print(f'note: dead-duplicate anchor found {n} (unicode check marks?), left as-is')

open(K, 'wb').write(c.replace('\n', '\r\n').encode('utf-8'))
print('KNOWLEDGE EVAL CONSTANTS APPLIED')

# 4. the gate test
T = r'C:\Users\pc\Desktop\BlackRose\cline\blackrose\src\tools\retrieval-eval.test.ts'
TEST = """// ---------------------------------------------------------------------------
// 2026-10-26 queue row: the 20-pair retrieval eval gate (blocks bulk ingest).
// Every chunking/embedding/ranking change ships unmeasured without it, and a
// large corpus can silently make answers worse. Fixed corpus, fixed questions,
// scored pass/fail - NOT a smoke test of "does ranking return something".
// Hermetic: BLACKROSE_EMBED=off forces the hash embedder, so the gate needs no
// key, no network and no quota.
// ---------------------------------------------------------------------------
import { strict as assert } from 'node:assert'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { test } from 'node:test'
import { knowledgeEvalTool, RETRIEVAL_EVAL_DOCS, RETRIEVAL_EVAL_QUERIES } from './knowledge.ts'

test('the gate is the size it claims: 12 documents, 20 fixed pairs, every expect is a document', () => {
  assert.equal(RETRIEVAL_EVAL_DOCS.length, 12, 'the canonical corpus is 12 documents')
  assert.equal(RETRIEVAL_EVAL_QUERIES.length, 20, 'the gate scores exactly 20 pairs')
  const sources = new Set(RETRIEVAL_EVAL_DOCS.map((d) => d.source))
  for (const { q, expect } of RETRIEVAL_EVAL_QUERIES) {
    assert.ok(sources.has(expect), `query "${q}" expects unknown source "${expect}"`)
  }
  // The gate must exercise the whole corpus, not one corner of it.
  const covered = new Set(RETRIEVAL_EVAL_QUERIES.map((x) => x.expect))
  assert.equal(covered.size, 12, `every document must be the expected answer somewhere (got ${covered.size})`)
})

test('retrieval eval gate: 20/20 offline, and the harness never touches the real store', async () => {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aki-gate-'))
  const prev = process.env.BLACKROSE_EMBED
  process.env.BLACKROSE_EMBED = 'off' // hermetic: hash embedder, no key, no network
  try {
    const r = (await knowledgeEvalTool.run({}, { cwd: dataDir, dataDir, askApproval: async () => true })) as {
      content: string
    }
    assert.ok(!r.content.includes('FAIL'), `a pair missed:\\n${r.content}`)
    assert.match(r.content, /result: 20\\/20 passed/, r.content)
    assert.ok(!fs.existsSync(path.join(dataDir, 'knowledge')), 'the eval must not touch the user knowledge base')
  } finally {
    if (prev === undefined) delete process.env.BLACKROSE_EMBED
    else process.env.BLACKROSE_EMBED = prev
    fs.rmSync(dataDir, { recursive: true, force: true })
  }
})
"""
open(T, 'wb').write(TEST.replace('\n', '\r\n').encode('utf-8'))
print('GATE TEST WRITTEN')

# 5. register in npm test
P = r'C:\Users\pc\Desktop\BlackRose\cline\blackrose\package.json'
c = open(P, 'rb').read().decode('utf-8')
old = 'src/tools/kb-ingest.test.ts'
if old not in c:
    old = 'src/memory/vectors.test.ts'
    new = 'src/memory/vectors.test.ts src/tools/retrieval-eval.test.ts'
else:
    new = 'src/tools/kb-ingest.test.ts src/tools/retrieval-eval.test.ts'
n = c.count(old)
assert n == 1, f'package anchor: {n}'
c = c.replace(old, new)
open(P, 'wb').write(c.encode('utf-8'))
print('REGISTERED IN npm test')
