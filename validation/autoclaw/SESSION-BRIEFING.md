# BlackRose — project briefing after the Cline session of 2026-10-22 → 10-27

> **STATUS 2026-10-28 (added after the briefing below was written):** §9 steps 1-4 are DONE.
> M9 is repaired in `9e2fbf0` — the defect described in §6 is closed and pinned by two tests that fail
> on the old code. `web_fetch` is now SSRF-guarded like `learn_url` (`04ac318`, new
> `src/core/publicFetch.ts` and `src/tools/web.test.ts`). The full gate is green on this tree
> (tsc 0, smoke PASSED, 414/414, `validation/gate-2026-10-28.out`). The missing 2026-10-27 record is
> now item 1 of the `SESSION 2026-10-28` block at the top of both checkpoint copies, and
> `53f596b..04ac318` is pushed (`0 0`). Step 5 — queue rows 137-139 — is untouched; §8's open items
> still stand as written, minus M9 and `web_fetch`.

> **Also learned (2026-10-28, `feee2d0`):** `build:exe` is a gate the test suite cannot replace. The
> bundler rewrites `import ... from` specifiers but **not** `export ... from`, so a re-export added for a
> test survived verbatim into `dist/blackrose.mjs` and made the bundle a SyntaxError — while tsc, smoke
> and all 414 tests stayed green. Do not add `export { x } from '...'` in any module that reaches the
> bundle. Final inner HEAD after this session: `feee2d0`, 35 commits past `v0.10.2`, pushed `0 0`;
> the bundle was rebuilt from it (128 modules, syntax ok, `--doctor` ok).

Compiled 2026-10-27 by AutoClaw. Everything below was read from disk or executed; claims that
were not verifiable are marked as such. This file is a briefing, **not** a checkpoint block —
`BLACKROSE_CHECKPOINT.txt` still has no entry for 2026-10-27 (see §7).

---

## 1. What the project is

BlackRose is a personal, model-independent AI operating layer for Windows, shipped as
`BlackRose.exe` / an NSIS installer. The product thesis (from
`BLACKROSE_AI_OS_PROJECT_INSTRUCTIONS.txt`, 58 numbered capabilities): one persistent identity
that can use many models, tools and devices, and that must never lose its memory, skills or
experience when the model or the machine changes.

Implemented reality is narrower and more concrete: a coding-agent-class runtime
(plan → act → observe loop, approval-gated tools, undo journal, persistent state in
`~/.blackrose`) plus a personal-memory/knowledge layer (memory, knowledge base, knowledge graph,
skills, mastery tracks, schedules, Telegram, web UI, remote bridge, encrypted portable state).

It is a **single-user, local-first** product. Multi-device sync exists but was closed as
"not needed" by owner decision on 2026-10-05 (single user, never shares the app).

---

## 2. Repository topology (important — two repos)

| Repo | Path | Role |
|---|---|---|
| Outer | `C:\Users\pc\Desktop\BlackRose` | Docs/checkpoint/roadmap + scratch validation evidence. Branch `master`, HEAD `63a4656`, **no tags**. |
| Inner | `C:\Users\pc\Desktop\BlackRose\cline\blackrose` | The actual product source. Branch `main`, HEAD `80dc2c3`, latest tag `v0.10.2`. |

The outer repo's `.gitignore` ignores `cline/`, so **the code repo is invisible to the outer
repo**. Two checkpoints exist and must stay byte-identical:
`BlackRose/BLACKROSE_CHECKPOINT.txt` and `cline/blackrose/docs/BLACKROSE_CHECKPOINT.txt`
(verified identical: sha256 `E85786E2…21EA82`), pinned by `npm run verify:checkpoint`.

---

## 3. Codebase at a glance (`cline/blackrose`)

- `package.json`: `blackrose@0.10.2`, `"type": "module"`, **zero runtime dependencies**,
  Node ≥ 24, sources run directly through Node's type stripping (`node src/index.ts`).
  No `build` script and no `doctor` script — "doctor" is `node src/index.ts --doctor`.
- `tsconfig.json`: ES2023 / NodeNext / `strict: true` / `noEmit: true` /
  `allowImportingTsExtensions` / `verbatimModuleSyntax`. Hence the pervasive `./x.ts` imports.
- **178 `.ts` files, 50,832 lines** in `src/` (131 non-test files).
- Module weight: `tools/` 18,472 · `ui/` 7,403 · `core/` 6,191 · `memory/` 3,085 · `llm/` 2,258
  · `bridge/` 1,120 · `mcp/` 683 · `session/` 597 · `state/` 377 · `skills/` 247 · `schedule/` 200.
- **161 tools**, all registered in one array in `src/tools/index.ts:124` (`buildTools()`).
  Contract in `src/core/tools.ts`. In-code note: `buildTool` defaults to **no approval**, and
  "98 of 157 built-ins inherit it" — every state-changing tool must declare its own gate.
- Four host surfaces over one core:
  1. CLI — `src/index.ts` (933 lines; `--goal --resume --ui --bridge --remote --doctor --ingest`).
  2. Web UI — `src/ui/web/main.ts` → `server.ts` (2,409 lines, ~40 `/api/*` routes);
     markup/CSS/JS embedded as strings in `assets.ts` (4,069 lines) so SEA packaging has no assets.
  3. Remote bridge — `src/bridge/` (token-auth HTTP, fail-closed approvals, audited).
  4. Desktop — `desktop/tauri/` Rust/Tauri v2 shell that spawns `node core/blackrose.mjs --ui`.
- Tests: `npm test` = `smoke.ts` (5,210 lines) **then** `node --test` over 43 of 46 `*.test.ts`
  (9,105 lines). Present but not wired into `npm test`: `tools/policy.test.ts`,
  `tools/repo.test.ts`, `tools/kb-ingest.test.ts` (498 lines) — no comment explains why.
- Build chain: `build:exe` = `tsc` emit → custom single-file bundler → Node SEA → `dist/BlackRose.exe`;
  `build:desktop` stages that bundle + a bundled node runtime into `desktop/tauri/` and runs `tauri build` (NSIS).
- Stale doc: `docs/03-ARCHITECTURE.md` still advertises a "202-check smoke test" and omits
  `core/{teams,workflow,plugins,policy,budget,undo}.ts`. Code wins over that file.

---

## 4. The previous Cline session (the one the user means)

| Field | Value |
|---|---|
| Session id | `session_1792661318728_zsxl1` |
| Store | `C:\Users\pc\.cline\data\sessions\session_1792661318728_zsxl1\` |
| Span | started 2026-10-22 09:29 UTC → ended 2026-10-27 16:38 UTC (~5 days, one session) |
| Source / model | `desktop`, provider `gonkarouter`, model `zai-org/GLM-5.3-Flash` |
| Size | 3,423 messages (3,252 before last compaction), 12.6 MB |
| Usage | 118.0 M input tokens, 707.8 K output, 72.3 M cache reads |
| Status | `failed`, `exit_code 1`, `failed_external_process_exit` (stale-session reconciler) |
| Opening ask | "ok checkout the entire project, once you are good with everything then lets start with what to build next" |

**Why it ended:** not a code problem. From 18:15 IST the harness itself was down —
`OpenCode returned no response data for model "glm-5.3-flash-free"`, then `Internal error.`,
then "Our service is being upgraded…", then repeatedly
`Failed to create session: {"code":"ConnectionRefused","path":"http://127.0.0.1:4096/session"}`.
The last four user turns ("cline doctor fix", "whats next") got nothing. The session was later
reaped by the stale-session reconciler. **No work was lost and nothing was left half-written.**

**Shape of the work:** five days of continuous audit-fix-release cycles driven by terse prompts
(".", "continue", "whats next", "check for bugs and mistakes", "cline doctor fix"), with the agent
choosing its own next item each time. It ran the project's own protocol: fix → test → commit →
update checkpoint.

**That session's final day (2026-10-27) produced four inner commits and one outer commit:**

| Commit | Time | What |
|---|---|---|
| `53f596b` | 06:18 | feat: retrieval eval gate — 12 docs / 20 query pairs extracted into exported constants, blocking gate test, registered in `npm test` |
| `c564173` | 06:33 | fix: audit M6 — an "exhausted" schedule run now backs off and disables after 5 resumes |
| `6b57a34` | 08:07 | fix: M9 fatal key handling (rotate instead of aborting the pool) + M7 `--resume` sorts by `updated` |
| `80dc2c3` | 17:21 | fix: L6 skill slug collision, L7 numeric XLSX sheet sort, L8 UI session auto-compaction |
| `63a4656` (outer) | 17:22 | checkpoint: adds the **2026-10-26 tier-4** block only — not the 10-27 work |

---

## 5. State of the tree right now (verified today)

- Both repos have **zero tracked changes**. Nothing is half-committed.
- Inner repo: **4 commits unpushed** (`git rev-list --left-right --count origin/main...HEAD` = `0 4`).
- `git describe` = `v0.10.2-27-g80dc2c3` → the version string is **27 commits behind HEAD**.
- `npx tsc --noEmit` → **0 errors** (178 src files, TS 5.9.3).
- `node --test src/audit-fixes.test.ts` → **12/12 pass**.
- Outer repo: tracked-clean but **54 untracked entries** — 46 `_*` scratch scripts, `.perch/`
  agent state, 6 validation logs, 1 scratch dir.
- **Build artifacts are stale relative to HEAD**: newest installer
  `BlackRose_0.10.2_x64-setup.exe` (24.69 MB) is from 2026-10-26 12:01; `dist/blackrose.mjs`
  is 2026-10-26 18:38; the staged `desktop/tauri/core/blackrose.mjs` (11:52) predates even that.
  No artifact exists for any 10-27 commit.
- Last full gate log is `validation/gate-followups.out` (2026-10-26 22:31, smoke PASSED,
  427/427 tests). **No full gate has been run on the 10-27 tree.**
  Note `validation/build-exe-subpath-gate.out` ends `SMOKE TEST FAILED` — superseded the same
  evening by the 22:31 pass, but it is still the last exe-build gate on disk.
- Released state: **v0.10.2 is live**, signed, payload-verified, tag on `d484374`, installed
  through the in-app updater. The shipped binary contains none of the 27 later commits.

---

## 6. Newly verified defect at HEAD (not in any checkpoint)

`cline/blackrose/validation/repro-m9-fatal-retry.ts` was left behind unexecuted, claiming the M9
fix in `6b57a34` is wrong: it `continue`s inside the inner retry loop instead of `break`ing out to
the next key. **I ran it.** It reproduces:

```
pool size: 2
backend: gemini, dims: 3, hashFallback: false
fetch calls: 6 (key0: 5, key1: 1)
wall time: 29.1s
REPRODUCED: fatal key retried 5x, healthy key tried 1x
```

Interpretation: with a dead primary key, the embedder burns the entire 5-attempt backoff ladder
(2+4+8+15 s) on a key that will never recover, *then* rotates. The audit fix removed the "whole
pool aborts to hash" behaviour but replaced it with a ~29 s stall on every embed call while a
fatal-erroring key sits at the head of the pool. `audit-fixes.test.ts` does not cover this path,
which is why 12/12 still passes.

---

## 7. Documentation gap

`BLACKROSE_CHECKPOINT.txt` (3,628 lines, 31 session blocks, newest at top) contains **zero**
mentions of `2026-10-27`, `80dc2c3` or `53f596b`. The newest block is `2026-10-26 TIER 4`.
Consequences:

- Three statements in the checkpoint are stale: the retrieval-eval gate is described as
  "STILL PENDING" (it shipped in `53f596b`); the audit tail is listed as "M6-M9 and L1-L8"
  when only M6/M7/M9 + L6/L7/L8 are done; and the 10-27 commits are invisible to any agent that
  follows the protocol (instructions file §2: "READ BLACKROSE_CHECKPOINT.txt SECOND").
- The outer commit message `63a4656` says "with audit fixes" but its diff is the 10-26 block only.

---

## 8. What is genuinely open

| # | Item | Status |
|---|---|---|
| 1 | **M9 fatal-key retry loop** (§6) | **Confirmed defect at HEAD.** One-line class of fix (`break` not `continue`), needs a regression test. |
| 2 | Audit tail **M8** — `.aistate` import inflates with no size cap | Open. Note: a separate `MAX_STATE_BYTES = 512 MB` exists elsewhere; the audit claims the *inflate* path is uncapped — verify before fixing. |
| 3 | Audit tail **L1–L5** — pdf total budget, zip member overshoot, 64-vs-256 MB comment drift, `MAX_BATCH` rationale, per-key retry ceiling × pool size | Open, low severity. L5 is the same shape as §6. |
| 4 | **Queue rows 137–139** — 137 teach-by-demo adjudication, 138 UI knowledge/graph viewer, 139 UI git/repo panel + undo | Open features, never started. |
| 5 | **Owner decision: `mini.ts` constitution default** | Open — must be asked, not chosen (checkpoint L1046). |
| 6 | **Owner decision: unguarded `web_fetch`** — `src/tools/web.ts` fetches arbitrary URLs with redirect-following and **no SSRF guard**, while `learn_url` is guarded (§ TIER 4 item 3). Same vulnerability class, bigger hole. | Open — flagged, deliberately not fixed. |
| 7 | **Owner decision: default approval gate is not fail-closed** (audit H3) | Open, behaviour deliberately unchanged. |
| 8 | **`kilo` route in the env chain has no adapter** — costs a warning row | Open, owner's call. |
| 9 | Three test files excluded from `npm test` | Open, unexplained. |
| 10 | Updater private key has a short, guessable password — **do not rotate casually** | Standing constraint. |

---

## 9. Recommended next sequence

1. **Fix M9 properly** (`break` out of the per-key retry ladder on a fatal status), add the
   regression test, and fold the repro into `audit-fixes.test.ts` so it can never regress silently.
2. **Run the full gate recipe on the 10-27 tree** and record it — the checkpoint's own rule is
   "gates per commit, not once at the end": `tsc --noEmit` → `node src/smoke.ts` →
   `node --test` (43 suites) → `npm run scan:secrets` (classify every fingerprint, never quote a
   literal) → `npm run verify:checkpoint` → bundle `--check` + `--doctor`.
3. **Write the missing `SESSION 2026-10-27` block** at the top of both checkpoint copies, covering
   `53f596b..80dc2c3`, retiring the retrieval-eval-gate line, and restating the audit tail honestly
   (M8 + L1–L5 still open). Mirror to `cline/blackrose/docs/BLACKROSE_CHECKPOINT.txt`, then
   `verify:checkpoint`.
4. **Push the 4 commits** (`0 4` → `0 0`).
5. Then pick up rows 137–139, or ask the owner the three decisions (mini constitution default,
   `web_fetch` SSRF, fail-closed approvals) before touching them.

---

## 10. Working conventions to respect

- Checkpoint is **append/prepend-only**, one block per session, never rewrite a body, run
  `verify:checkpoint` before committing. Line-slicing edits destroyed history three times.
- Commit style: `fix:` / `feat:` / `test:` / `docs:` + the behaviour change + its proof.
  Commit messages must state the security-scan verdict **as it is**, not as it is hoped to be.
- Owner decisions are asked, never taken silently. High-risk/irreversible actions need approval.
- Never trust a stale `dist-build/` — rebuild rather than ship an existing artifact.
- Do not re-open findings already closed as HIGH (adapter groups, panic paths).
- "Verify claims against reality before reporting them. Run the command, read the output."

---

## 11. Detail files

- `validation/autoclaw/codebase-map.md` — full structural map, per-directory LOC, all 161 tools.
- `validation/autoclaw/checkpoint-digest.md` — the 31 checkpoint blocks digested, every open item
  with line numbers, the 10-27 discrepancy argued from git.
- `validation/autoclaw/git-state.md` — both repos: HEADs, 12-commit logs, tags, artifacts,
  validation logs, tsc result.
- `C:\Users\pc\.cline\data\sessions\session_1792661318728_zsxl1\` — the raw previous session
  (`.messages.json` 12.6 MB, `.compaction.json`, `.json` metadata).
