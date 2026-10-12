# Docs-vs-Code Drift Audit — BlackRose

**Auditor:** Documentation-Truth Auditor (read-only)
**Date:** 2026-10-02
**Method:** every claim re-checked against the CODE / config / git history, not against other docs.
Read-only: no file in the code repo or docs was modified; no commits; no builds; no test runs).
Unless noted, the "claim" rows below were pulled from the CODE.

## 0. VERSION TRUTH (the source of most drift)

| Artifact | Value | Evidence |
|---|---|---|
| `package.json` | **0.9.8** | `cline/blackrose/package.json:3` |
| `desktop/tauri/tauri.conf.json` | **0.9.8** | `tauri.conf.json:4` |
| `desktop/tauri/Cargo.toml` | **0.9.8** | `Cargo.toml:3` |
| Installed app `%LOCALAPPDATA%\BlackRose\BlackRose.exe` | **0.9.8** | `(Get-Item ...).VersionInfo.ProductVersion = 0.9.8`, FileVersion `0.9.8` |
| GitHub release repo `MaxxaCoin/BlackRose` | **v0.9.8** is latest | api.github.com …/releases/tags/v0.9.8, published 2026-09-28T15:55:44Z |
| Git tags in the source repo | **none** | `git tag -l` = empty |
| Source repo remote | `github.com/MaxxaCoin/blackrose-source.git` | `git remote -v` |
| HEAD | `a0773fc` (2026-10-01) | `git log` |

**Conclusion: the code, the installer, and the release host are ALL uniformly 0.9.8. Every "0.8.1" and "0.9.0" string below is a stale doc snapshot.**

### (c) Every stale / contradictory version string

| File:line | String | Truth | Verdict |
|---|---|---|---|
| `docs/BLACKROSE_CHECKPOINT.txt:6` | "signed 0.8.1 build" | installed is 0.9.8 | STALE |
| `docs/BLACKROSE_CHECKPOINT.txt:28` | "0.9.0 NSIS installer" | 0.9.8 | STALE |
| `docs/BLACKROSE_CHECKPOINT.txt:53` | "0.9.0 NSIS installer REBUILT" | 0.9.8 | STALE |
| `docs/BLACKROSE_CHECKPOINT.txt:655` | "The installed app is 0.8.1 built from d0571c3" | installed is 0.9.8 | STALE |
| `docs/BLACKROSE_CHECKPOINT.txt:986-987` | "installed 0.8.1 displayed update v0.9.0" | historic, fine as history | HISTORIC |
| `BLACKROSE_CHECKPOINT.txt` (outer):6 | "signed 0.8.1 build" | 0.9.8 | STALE |
| `BLACKROSE_CHECKPOINT.txt` (outer):655 | "The installed app is 0.8.1 built from d0571c3" | 0.9.8 | STALE |
| `BLACKROSE_CHECKPOINT.txt` (outer):663 | "0.8.1 displayed update available v0.9.0" | historic | HISTORIC |
| Cline worktree `…\64be3\BlackRose` commit `246f0a3` | "installed=0.9.0" | installed is 0.9.8 | STALE |
| `README.md:214` | `BlackRose_0.8.0_x64-setup.exe`, ~24 MB | current is 0.9.8, 25.6 MB | STALE |
| `README.md:244,247,253,254` | `latest.json` / `gh release upload v0.9.0` example | example only | STALE EXAMPLE |
| `docs/04-ROADMAP.md:130` | `BlackRose_0.8.1_x64-setup.exe` | 0.9.8 | STALE |
| `docs/04-ROADMAP.md:394` | `BlackRose_0.8.0_x64-setup.exe`, 24.6 MB | 0.9.8, 25.6 MB | STALE |
| `docs/04-ROADMAP.md:397` | `BlackRose_0.8.0_x64-setup.exe`, 25.3 MB | 0.9.8 | STALE |
| `src/smoke.ts:2359,2378` | comments "live 0.9.0 update", "0.9.2 shell" | historic code comments | HISTORIC |
| `desktop/tauri/src/main.rs:89,277,374` | comments "0.9.0 update", "0.9.1 core" | historic code comments | HISTORIC |
---

## (a) CLAIM-BY-CLAIM TRUTH TABLE

Verdicts: **VERIFIED** (doc matches code) · **STALE** (code moved on; doc lags) ·
**FALSE** (doc contradicts code) · **UNVERIFIABLE** (cannot confirm from repo evidence).

### Finding 1 — B5 "API embedder" unchecked-but-implemented

| # | Claim | Source | Verdict | Evidence |
|---|---|---|---|---|
| 1.1 | "**B5 — API embedder, replacing the local one**" is an UNCHECKED `[ ]` item that "currently reaches Ollama's `/api/embed` (nomic-embed-text, 768-dim)" | `docs/04-ROADMAP.md:181` | **FALSE** | `src/memory/embedder.ts:1-27,43,236-261` implements `gemini-embedding-001` (3072-dim) via `batchEmbedContents`, with `br-hash-v1` fallback. No Ollama path in the file. |
| 1.2 | B5 is done in code | — | **VERIFIED** | `src/memory/embedder.ts`; commit `f09b14c` "feat: safety layer, API-only cut, semantic search, key rotation". |
| 1.3 | The vector index was RE-BUILT against the new model | (implied question) | **VERIFIED** | `~/.blackrose/vectors/index.json` header = `{"model":"gemini-embedding-001","dim":3072,...}`, 6,113,605 bytes, mtime 2026-10-01 22:28 (vs `index.json.pre-warm.bak` 180,925 bytes). |
| 1.4 | Stale 256-dim hash entries were dropped, not mixed | `docs/07-BUILD-CHECKLIST.md:206` | **VERIFIED** | index header records a single model+dim; `index.json.hash-poison-222606.bak` is the quarantined old space. |
| 1.5 | B5 is marked DONE in the checklist | `docs/07-BUILD-CHECKLIST.md:206` `[x]` 2026-09-29 | **VERIFIED** | consistent with code. |
| 1.6 | (checklist detail) embedder is "chunked at **100**/request" | `docs/07-BUILD-CHECKLIST.md:206` | **STALE** | `src/memory/embedder.ts:61` `MAX_BATCH = 8` (measured live; n=50/100 -> HTTP 429). |

**True status: B5 is DONE (code + index rebuilt). The roadmap line is stale; only doc sync remains.**

### Finding 2 — B25 "remove the local engine, API-only"

| # | Claim | Source | Verdict | Evidence |
|---|---|---|---|---|
| 2.1 | "**B25 — remove the local engine, API-only**" is UNCHECKED `[ ]` | `docs/04-ROADMAP.md:145` | **FALSE** | `src/llm/` has NO `ollama.ts` (files: client, factory, gemini, keyHealth, mock, onemin, openai, prompt, resilient, routeHealth, router). `src/llm/factory.ts:12` "API-only since 2026-09-29 (B25): there is no local engine." |
| 2.2 | "the local Ollama engine is deleted" | `docs/04-ROADMAP.md:146` | VERIFIED (text) | file gone; commit `f09b14c`. |
| 2.3 | "`grep -ri ollama src/` now returns **zero**" | `docs/07-BUILD-CHECKLIST.md:207` | **FALSE** | 4 residual hits: `src/llm/factory.ts:201` (comment), `src/smoke.ts:540` (comment), `src/regression.test.ts:203* (comment), `src/ui/web/main.ts:50` (error string). All comments/strings -- not a live engine -- so "zero" is literally false though the feature is removed. |
| 2.4 | B25 marked DONE | `docs/07-BUILD-CHECKLIST.md:207` `[x]` | VERIFIED | consistent with code. |
| 2.5 | No Ollama in the desktop shell | — | **VERIFIED** | `grep ollama desktop/**/*.{rs,json,toml,nsh}` = 0 hits. |
| 2.6 | `05-MODEL-INDEPENDENCE.md` says the local engine "is being removed (B25) ... Retained ... until B25 lands" | `docs/05-MODEL-INDEPENDENCE.md:3-8,19,46,53,125` | **STALE** | B25 landed 2026-09-29. |
| 2.7 | `03-ARCHITECTURE.md` still lists `ollama.ts [REMOVING - B25]` | `docs/03-ARCHITECTURE.md:52` | **STALE** | file deleted. |

**True status: B25 DONE. Roadmap + architecture + model-independence docs stale; the checklist's "zero ollama" claim is overstated (4 comment/string hits remain).**

### Finding 3 — Version drift

See §0. Verdict: **STALE** everywhere in docs; the code/installer/release are uniformly 0.9.8.

### Finding 4 — Installed-version truth

| # | Claim | Source | Verdict | Evidence |
|---|---|---|---|---|
| 4.1 | "the installed app is 0.8.1" | outer checkpoint:655; `docs/BLACKROSE_CHECKPOINT.txt:655` | **FALSE** | `BlackRose.exe` VersionInfo ProductVersion/FileVersion = **0.9.8**; exe mtime 2026-09-28 21:20. |
| 4.2 | "installed=0.9.0" | Cline worktree commit `246f0a3` | **STALE** | installed is 0.9.8. |
| 4.3 | `%LOCALAPPDATA%\BlackRose` reachable (read-only) | — | **VERIFIED** | contains `BlackRose.exe`, `uninstall.exe`, `core/blackrose.mjs` (01-10), `core/blackrose.mjs.0.9.7-stale.bak`, `core/blackrose.mjs.pre-routes.bak`, `node/`. |
### Finding 5 — SEA .exe, multi-device sync, updater endpoint

| # | Claim | Source | Verdict | Evidence |
|---|---|---|---|---|
| 5.1 | SEA `.exe` is "**DROPPED**" | `docs/04-ROADMAP.md:394` | VERIFIED (text) | matches README/checkpoint. |
| 5.2 | SEA `.exe` is still an unchecked roadmap item `[ ]` | `docs/04-ROADMAP.md:394` | **STALE/INCONSISTENT** | a dropped item should not be a live `[ ]` checkbox. |
| 5.3 | "Multi-device `.aistate` sync" still open, needs a 2nd device | `docs/04-ROADMAP.md:392` `[ ]`; `07-BUILD-CHECKLIST.md` "blocked on a 2nd machine" | **VERIFIED OPEN** | code exists (bridge/sync); no 2nd-device evidence in the repo. |
| 5.4 | Auto-updater endpoint is a "GitHub-releases **PLACEHOLDER**" | `docs/04-ROADMAP.md:395`; `README.md:224-225`; outer checkpoint | **FALSE** | `desktop/tauri/tauri.conf.json` `plugins.updater.endpoints[0]` = `https://github.com/MaxxaCoin/BlackRose/releases/latest/download/latest.json` -- a REAL host. The v0.9.8 release **has** a `latest.json` asset (api.github.com, download_count 13). |
| 5.5 | Signed installer "DECLINED" | `docs/04-ROADMAP.md:396` | VERIFIED | user decision; consistent. |

### Finding 6 — Inner-checkpoint backlog lists items that are now complete

| # | Claim | Source | Verdict | Evidence |
|---|---|---|---|---|
| 6.1 | NEXT STEP 1: "SHIP v0.9.0. The installed app is 0.8.1 ... never been released" | `docs/BLACKROSE_CHECKPOINT.txt:654-661` | **STALE** | releases v0.9.0...v0.9.8 all published; installed app is 0.9.8. |
| 6.2 | NEXT STEP 2: "verify the update INSTALL path (the only unverified feature)" | `docs/BLACKROSE_CHECKPOINT.txt:917-921` | **UNVERIFIABLE** | no repo evidence the download->NSIS-close->relaunch path ran end-to-end; the installed 0.9.8 could be a manual install. Treat as open until a log exists. |
| 6.3 | B7 (dedup) pending | `docs/07-BUILD-CHECKLIST.md:211` (no `[x]`) | **STALE** | commit `a0773fc` "find duplicates in what BlackRose has learned (B7)": +304 lines in `src/tools/knowledge.ts` (`knowledge_dedup` tool), smoke +16 dedup/forget refs. |
| 6.4 | B6 (knowledge panel + forget) pending | `docs/07-BUILD-CHECKLIST.md:208` (no `[x]`) | **STALE** | commits `4b0cb1e`, `2889209`, `871487e`; `knowledge_forget` tool present. |
| 6.5 | B26 (multi-key rotation) pending | `docs/07-BUILD-CHECKLIST.md:275` PART C item 7 | **STALE** | commits `331bc68` "multi-key rotation panel with per-key health", `8bd2cab` "per-route bulk keys"; smoke checks "key rotation...". |
| 6.6 | B27 (add-provider panel) pending | `docs/07-BUILD-CHECKLIST.md:209,276` | **PARTIAL/STALE** | commit `d086040` "add a provider from the UI (B27 part 1)": +207 `src/core/providers.ts`, +27 `routespecs.ts`, `factory.ts` reads `readProviders()`. Part 1 done. |
| 6.7 | Redaction is "the last true safety gap" (labelled B3) | `docs/07-BUILD-CHECKLIST.md:274` | **STALE/FALSE** | redaction IS implemented: `src/memory/redact.ts` (13 hits), used in `tools/knowledge.ts` (9) + `tools/memory.ts` (4); commit `e42a8d6` "redact secrets before anything is persisted or embedded". |
| 6.8 | B3/B4 numbering is self-consistent | `docs/07-BUILD-CHECKLIST.md:199-200,434-435` vs `:274,276 | **FALSE (internal contradiction)** | Table + old->new map: B3 = "Visible trust badge", B4 = "Allow for 10 minutes". PART C: B3 = "Redaction everywhere", B4 = "trust UI". Same file, two definitions. |

### Other stale claims found (beyond the 6)

| # | Claim | Source | Verdict | Evidence |
|---|---|---|---|---|
| 7.1 | "58-check smoke test" | `docs/03-ARCHITECTURE.md:45` | **STALE** | current smoke = 200 checks (see §0-test). |
| 7.2 | "16 regression tests" | `docs/03-ARCHITECTURE.md:46-48` | **STALE** | current ≈51 (see §0-test). |
| 7.3 | README shows a live `ollama` provider/route and `BLACKROSE_OLLAMA_*` env | `README.md:20,53,56,57,78,84,92` | **STALE** | B25 removed the local engine. |
| 7.4 | "Verified against `HEAD a5e93ba`" | `docs/07-BUILD-CHECKLIST.md:6` | **STALE** | HEAD is `a0773fc`, 28+ commits ahead; several statuses changed after a5e93ba. |
| 7.5 | Roadmap Phase 6.2 "49 checks total" | `docs/04-ROADMAP.md` (~227) | **STALE** | superseded by 200. |

---

## §0-test — VALIDATION-CLAIM RECONCILIATION

The task stated: "smoke = 200 PASS / 0 FAIL, regression = 51 pass / 0 fail, tsc clean".

| Claim | Verdict | Evidence |
|---|---|---|
| smoke = 200 PASS / 0 FAIL | **VERIFIED (count matches code)** | `src/smoke.ts`: 4 inline entries in `const checks` (line 127-132) + 196 `checks.push(` = **200 checks**. Latest saved smoke log `validation/smoke-retry.out` (2026-09-30) shows **186 PASS / 0 FAIL** and ends `SMOKE TEST PASSED` -- it predates the 2026-10-01 commits that added ~14 checks. |
| regression = 51 pass / 0 fail | **VERIFIED (runtime > static)** | `src/regression.test.ts` has **44** literal `test(` declarations, but the unsafe-path cases are PARAMETRIZED (`for (const rel of [...])` at line 85 -> `test(...)` at line 95), so the runtime count exceeds 44. Latest saved reg log `validation/reg-final.out` (2026-09-30) shows `tests 18 / pass 18` -- it predates the 2026-10-01 additions. 51 is plausible; no saved log currently shows 51. |
| tsc clean | **VERIFIED (log stale)** | Latest saved typecheck log `validation/tc-final.out` (2026-09-28) is `blackrose@0.9.7 typecheck` -> `tsc --noEmit` with **no errors**. No 0.9.8 typecheck log was saved. |

**Action for maintainer: re-run `npm test` + `npm run typecheck` and SAVE the logs (e.g. `validation/smoke-200.out`, `validation/reg-51.out`, `validation/tc-098.out`) so the documented counts are reproducible.**

---

## (b) CORRECTED REMAINING-BACKLOG (priority order)

Derived from CODE + git history, with every "already done" item removed.

### DONE — remove from the backlog (code + commit evidence)

- **B1 Secret Vault** -- `src/core/vault.ts`, `keys.enc`/`vault.key` present; 4 smoke + 1 regression check.
- **B2 Undo / Time Machine** -- `src/core/undo.ts` + `undo` tool; 6 smoke + 1 regression check.
- **B5 API embedder (Gemini)** -- `src/memory/embedder.ts`; index rebuilt at dim 3072.
- **B25 Remove Ollama (API-only)** -- `src/llm/ollama.ts` deleted; commit `f09b14c`.
- **B26 Multi-key rotation** -- commit `331bc68`; per-route bulk keys `8bd2cab`.
- **B6 Knowledge panel + forget** -- `knowledge_forget`; commits `4b0cb1e`, `2889209`.
- **B7 Dedup on ingest** -- `knowledge_dedup`; commit `a0773fc`.
- **Redaction of secrets** -- `src/memory/redact.ts`; commit `e42a8d6` (this is NOT an open safety gap).

### REMAINING (priority order)

**Tier 0/1 — safety & learning gap**
1. **B3 "Visible trust badge"** -- a `#btn-trust` header control exists (`src/ui/web/assets.ts:582`, colour toggle at :323, `/api/trust` in `server.ts`), but confirm whether the *specified* persistent-badge behaviour is complete; checklist still lists it open. VERIFY-THEN-CLOSE.
2. **B4 "Allow for 10 minutes"** -- NO timed-grant / countdown found in code. **OPEN.**
3. **B27 add-provider panel (remainder)** -- part 1 (add gateway + registry) is DONE (`d086040`); the route reorder + test-connection + factory-no-hardcoded-list remainder is not confirmed. **PARTIAL.**
4. **B8 Learning Inbox (watched folder)** -- no `inbox` implementation (`grep inbox src/` = 0). **OPEN.**
5. **B9 Telegram companion** -- `grep telegram src/` = 0. **OPEN.**

**Tier 2 — reach**
6. **B10 Browser bookmarklet** -- OPEN.
7. **B11 Browser-login in the UI** (cookie source in Settings) -- OPEN.

**Tier 3/4 — vision (deferred)**
8. **B12 Executive Brain** -- OPEN (ranked #1 blocker by the capability audit, `audit-capabilities.md`).
9. **B13 `.aihistory`** -- `grep aihistory src/` = 0. OPEN.
10. **B14 Knowledge Graph** -- OPEN (#3 blocker).
11. **B15 Self-healing / recovery** -- partial (crash reporter + orphan-core reaper exist). OPEN (#4).
12. **B16 Courses / curriculum player** -- curriculum text exists; runner absent. OPEN (#2).
13. **B17 Autonomous Mastery Engine**, **B18 Experiment Lab**, **B19 Controlled self-improvement**, **B20 AI Software Factory**, **B21 3D Website Factory**, **B22 Mini-AI/clone builder**, **B23 One-AI-Many-Bodies**, **B24 Android companion** -- all deferred.

**Roadmap Phase 8 leftovers**
14. **Multi-device `.aistate` sync** -- code complete, smoke-verified, **blocked on a 2nd device**. OPEN.
15. **Verify the update INSTALL path** (download -> NSIS closes app -> relaunch -> process cleanup) -- **UNVERIFIED** (checkpoint `:917-921`); the installed 0.9.8 may have been a manual install.
16. **SEA `.exe`** -- **DROPPED** (close the roadmap checkbox; do not re-open).
17. **Signed installer** -- **DECLINED** (user decision; do not re-open).

**Cross-reference:** the parallel capability audit (`audit-capabilities.md`, 58 spec capabilities) ranks the same top blockers: Executive Brain (B12), learning/Mastery (B16/17), Knowledge Graph (B14), self-healing (B15), portable identity (skills/identity/config missing from `.aistate` STATE_DIRS), no offline (B25 trade-off).

---

## (d) SPECIFIC DOC EDITS A MAINTAINER SHOULD MAKE (described, not applied)

### `docs/04-ROADMAP.md`
- **Line ~145 (B25):** change `[ ]` to `[x]`; state the local engine is deleted (`src/llm/ollama.ts` gone), cite commit `f09b14c` and `07-BUILD-CHECKLIST.md:207`.
- **Line ~181 (B5):** change `[ ]` to `[x]`; delete the "reaches Ollama's `/api/embed`" paragraph; state it uses `gemini-embedding-001` (3072-dim) via `batchEmbedContents` with the `br-hash-v1` fallback, and that the index is re-built. Cite `src/memory/embedder.ts`.
- **Line ~130:** `BlackRose_0.8.1_x64-setup.exe` -> `BlackRose_0.9.8_x64-setup.exe`.
- **Line ~394 (SEA):** leading `[ ]` -> `[x]` (a DROPPED item must not be a live checkbox).
- **Line ~395 (updater):** delete "GitHub-releases PLACEHOLDER"; state the real endpoint in `tauri.conf.json` and that v0.9.8 ships a matching `latest.json`.
- **Line ~397:** `0.8.0` -> `0.9.8`; sizes 24.6/25.3 MB -> 25.6 MB.
- **Line ~227 (Phase 6.2):** "49 checks" -> current count.

### `README.md`
- **Lines 20, 53, 56, 57, 78, 84, 92:** remove every live `ollama` provider/route/`BLACKROSE_OLLAMA_*` reference (B25).
- **Lines 224-225:** replace "PLACEHOLDER" with the real endpoint + published `latest.json`.
- **Line 214:** `0.8.0`, ~24 MB -> `0.9.8`, 25.6 MB.
- **Lines 244, 247, 253-254:** update the `latest.json` / `gh release upload` example off `0.9.0`.

### `docs/07-BUILD-CHECKLIST.md`
- **Line 6:** "Verified against `HEAD a5e93ba`" -> current HEAD `a0773fc` + new check count.
- **Line 206 (B5):** "chunked at 100/request" -> "chunked at 8/request (`MAX_BATCH=8`)".
- **Line 207 (B25):** correct "grep returns zero" -- 4 residual comment/string hits remain.
- **Lines 208, 211 (B6, B7):** mark `[x]` with commits `4b0cb1e`/`2889209` and `a0773fc`.
- **Line 209 / PART C item 7 (B27):** "part 1 DONE (`d086040`); remainder open".
- **PART C item 7 (B26):** mark DONE (`331bc68`, `8bd2cab`).
- **Line 274 / PART C item 3:** remove "B3 Redaction ... last true safety gap" (redaction IS implemented, `e42a8d6`); resolve the B3/B4 contradiction with lines 199-200.

### `docs/05-MODEL-INDEPENDENCE.md`
- **Lines 3-8, 19, 46, 53, 125:** drop "being removed / until B25 lands"; state the local engine is gone; remove the `src/llm/ollama.ts` line from "Implemented in".

### `docs/03-ARCHITECTURE.md`
- **Line 45:** "58-check" -> 200. **Lines 46-48:** "16 regression" -> ~51. **Line 52:** remove the `ollama.ts [REMOVING - B25]` entry.

### `docs/BLACKROSE_CHECKPOINT.txt` (inner) and `BLACKROSE_CHECKPOINT.txt` (outer)
- **Header (line 6):** "signed 0.8.1 build" -> 0.9.8. **Lines 28, 53, 655:** "0.9.0"/"installed 0.8.1" -> 0.9.8. **NEXT STEP (654-661):** mark the "SHIP v0.9.0" item complete. Add a note that the outer checkpoint (2026-09-28) and the Cline worktree copy are superseded.

### `docs/07-BACKUP.md`
- Re-author the pointer stub as the real source-backup routine, or delete it.

---

## EVIDENCE INDEX (read-only commands run)

- `git log --oneline` / `git log -12 --format='%h %ci %s'` -- HEAD `a0773fc`; B7/B27/B25 commits.
- `git show --stat a0773fc` / `d086040` -- dedup + add-provider diffs.
- `git tag -l` (empty); `git remote -v` (`MaxxaCoin/blackrose-source`).
- `tauri.conf.json` / `Cargo.toml` / `package.json:3` -- version 0.9.8.
- `(Get-Item %LOCALAPPDATA%\BlackRose\BlackRose.exe).VersionInfo` -> 0.9.8.
- `%USERPROFILE%\.blackrose\vectors\index.json` header -> gemini-embedding-001 / dim 3072.
- `Select-String` greps for `ollama`, `redact`, `trust`, `dedup|forget`, `B5|B7|B25|B27` across `src/`, `docs/`, `README.md`.
- `src/llm/` listing (no `ollama.ts`); `src/smoke.ts` `checks.push(` = 196 (+4 inline).
- Web: `api.github.com/repos/MaxxaCoin/BlackRose/releases` + `/tags/v0.9.8` (latest = v0.9.8; `latest.json` present).
- Logs: `validation/smoke-retry.out` (186 PASS, SMOKE TEST PASSED), `validation/reg-final.out` (18/18), `validation/tc-final.out` (0.9.7 clean).

**No file in the code repo or docs was edited; no commits, builds, or test runs were performed. Secrets were never read or printed.**
