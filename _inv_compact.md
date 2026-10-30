# Investigation: `/compact` leaves an orphan tool_result at the head

Repo: `C:\Users\pc\Desktop\BlackRose\cline\blackrose` (v0.10.2, Node 24, zero-dep, `--experimental-strip-types`).
Read-only investigation; `src/` untouched. Scratch proofs live in `validation/repro-compact-orphan.ts` (reproduces, exit 1) and `validation/repro-compact-fixed.ts` (patched copy, exit 0).

## 1. Defect location and mechanism — CONFIRMED (deterministic repro)

**Splice site:** `src/session/history.ts`, function `compactHistory` — splice at **line 265-266** (`messages.slice(0, len - keepLast)` / `slice(-keepLast)`), re-anchor at **lines 287-291**, return at **line 292**.

```ts
287:  // the kept tail must start with a user turn for strict alternation
288:  if (recent[0]?.role !== 'user') {
289:    const firstUser = recent.findIndex((m) => m.role === 'user')
290:    recent = firstUser === -1 ? recent : recent.slice(firstUser)
291:  }
292:  return { messages: [summary, ...recent], removed: old.length }
```

**Mechanism — two distinct orphan paths, both confirmed by running the real function:**

The history format is Anthropic-wire-style (`src/types.ts:39-42`): a tool result is a **user-role** message whose `content` is `ToolResultBlock[]`, immediately following the assistant message carrying the matching `tool_use` (produced by `core/agent.ts:336-338`).

- **Path A (no re-anchor):** if `recent[0].role === 'user'` the guard at 288 does nothing — but that user message can be a tool_result carrier whose pairing `tool_use` assistant sits at the last position of the folded-away `old` slice. Result: `[summary(user), user(tool_result), …]`.
- **Path B (re-anchor creates it):** if `recent[0].role !== 'user'`, line 289-290 slices to the **first user message** — which can be exactly the tool_result carrier whose pairing assistant `tool_use` was just sliced off. The alternation guard actively manufactures the orphan.

The check is role-only (`m.role === 'user'`); it never inspects content block types, so a `tool_result` block with no preceding `tool_use` in the same stream survives at position 1. Anthropic rejects a leading/unpaired `tool_result` ("unexpected tool_use_id"); the OpenAI adapter (`llm/openai.ts:97-101`) emits a `role:"tool"` message with no preceding assistant `tool_calls`, which OpenAI also rejects.

**Why no downstream net:** `runAgent` sends `trimHistory(o.history)` (`core/agent.ts:180`), and `trimHistory` does have an anti-orphan while-loop (`core/agent.ts:134-140`) — but only on the over-budget path; the early return at `agent.ts:117` (`before <= maxChars`, default 100k chars) returns the history **unsanitized**. A freshly compacted history is almost always under budget, so the orphan reaches the adapter verbatim.

**Reproduction evidence** (`node --experimental-strip-types validation/repro-compact-orphan.ts`, imports the real `compactHistory`, exit code 1): both Case A (boundary lands on tool_result user message, keepLast=3) and Case B (re-anchor lands on it, keepLast=4) output `[summary(user), user([{type:'tool_result',…}]), assistant, user]` — orphan at head = true.

## 2. Minimal fix (function + logic, in codebase style)

In `compactHistory` (`src/session/history.ts`), immediately after the re-anchor block (after line 291, before line 292), add the same guard already used by `trimHistory` in `core/agent.ts:134-140`:

```ts
  // Never start the kept window on an orphaned tool_result: its matching
  // tool_use may have been folded into the summary, and providers reject a
  // history whose tool_result has no matching tool_use.
  while (recent.length > 0) {
    const head = recent[0]!
    const startsWithToolResult =
      typeof head.content !== 'string' && head.content.some((b) => b.type === 'tool_result')
    if (!startsWithToolResult) break
    recent.shift()
  }
```

Safety of dropping from the front: a tool_result user message always immediately follows its tool_use assistant, so any dropped tool_result's tool_use was dropped too (it lies earlier in the removed prefix — either folded into `old` or cut by the re-anchor slice); no intra-tail tool_use/tool_result pair is split. Degenerate all-tool_result tail degrades to summary-only, which is valid. Verified: patched copy (`validation/repro-compact-fixed.ts`) leaves no orphan in either case (exit 0) and preserves the summary + kept-tail structure.

## 3. Regression test

**File:** `src/smoke.ts`, add a check block next to the existing Phase 6.3 compact checks (lines 2384-2395) — that is where `compactHistory` is currently tested (`checks.push([...])` pattern, run by `npm test`). Assert for both constructed cases (tool_result at the slice boundary; tool_result as the first user inside an assistant-led tail):

- `comp.messages` contains **no** message before the first non-tool_result message whose array content includes a `tool_result` block (i.e., `comp.messages[1]` is not a tool_result carrier), and
- any `tool_use` remaining in `comp.messages` is followed by its matching `tool_use_id` result.

**Evidence it FAILS against current code:** `validation/repro-compact-orphan.ts` imports the unmodified `compactHistory` and exits 1 with both cases showing the orphan at head (output captured above, run 2026-10-26). The patched copy (`validation/repro-compact-fixed.ts`) exits 0, so the same assertion passes post-fix. Alternative placement: a new `src/session/history.test.ts` in `node --test` style (added to the `test` script in package.json); smoke.ts is the lower-friction option since compact checks already live there.

## 4. Adjacent callers

- `src/index.ts:934-937` (CLI REPL `/compact`): assigns `history = r.messages` and persists via `saveSession`. No change needed once `compactHistory` is fixed; the fix must live in `compactHistory` (not here) because this caller also persists the result.
- `src/tools/telegram.ts:2645-2655` (`compactHistoryCmd`, dispatched at telegram.ts:3097): same — benefits automatically, no code change.
- `src/smoke.ts:2384-2395`: existing checks only use plain text messages, which is exactly why the bug was never caught — the new regression cases close that gap.
- Non-caller worth noting: `core/agent.ts` `trimHistory` is unaffected; its budget-gated guard does not and should not be relied on to mask this bug (orphan must not be persisted by `saveSession` either — index.ts:937 persists the compacted array).

## Evidence tiers

- First-hand code: history.ts:263-292, agent.ts:114-150/180, types.ts:32-42, index.ts:934-937, telegram.ts:2645-2655, smoke.ts:2384-2395 — read 2026-10-26.
- On-run proof: validation/repro-compact-orphan.ts (exit 1, real function), validation/repro-compact-fixed.ts (exit 0, patched copy).
- Provider rejection behavior (Anthropic/OpenAI reject leading/unpaired tool_result) is stated in the repo's own comments (agent.ts:109-110, smoke.ts:513-514) and the task context; not independently verified against provider docs in this run.
