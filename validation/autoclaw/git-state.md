# BlackRose — read-only git & build-state audit

Date: 2026-10-27
Scope: read-only inspection only. No commit, reset, checkout, delete, or build was performed.
Repos audited:

- Root: `C:\Users\pc\Desktop\BlackRose`
- Sub-repo: `C:\Users\pc\Desktop\BlackRose\cline\blackrose` (nested; root's `.gitignore` line 4 ignores `cline/`, so the code repo is invisible to the root repo)

---

## 1. Repo state

### Root repo — `C:\Users\pc\Desktop\BlackRose`

| Field | Value |
|---|---|
| Branch | `master` |
| HEAD | `63a4656f17e2f6a975d08e9063247f95a9413429` |
| HEAD subject | checkpoint: 2026-10-26 session wrap-up with audit fixes and handoff notes |
| Tracked files | 1005 |
| Modified/added/deleted tracked files | **0** (`git status --porcelain --untracked-files=no` → 0 lines) |
| Untracked entries | 54 |
| Tags | **none** (0 tags) |

Last 12 commits:

| SHA | Date | Subject |
|---|---|---|
| 63a4656 | 2026-10-27 | checkpoint: 2026-10-26 session wrap-up with audit fixes and handoff notes |
| eb5d8e4 | 2026-10-26 | checkpoint 2026-10-26: tier 2 closed - stale sandbox, atomic writes, undo GC rule |
| ba756b1 | 2026-10-26 | checkpoint 2026-10-26: tier 1 closed - policy shell rules, llm status first, budget cross-process lock |
| 38f21e5 | 2026-10-26 | checkpoint 2026-10-26: updater-key posture noted - release chain closed and clean |
| 1107a41 | 2026-10-26 | checkpoint 2026-10-26: post-release update-install verified - release chain closed |
| 9ac1934 | 2026-10-26 | checkpoint 2026-10-26: v0.10.2 published - signed, payload-verified, live |
| 0558477 | 2026-10-26 | checkpoint 2026-10-26: full recheck before 0.10.2 - sweep 2 closed 3 HIGH + 7 MED, gates green |
| 174ba06 | 2026-10-25 | checkpoint 2026-10-25: audit of the previous agent - panic paths consolidated, release still ready |
| dd87f99 | 2026-10-24 | checkpoint 2026-10-24: self-review pass - 6 defects fixed (9c2c01a), server.ts scan fingerprints classified, release blockers stay closed |
| fb483c2 | 2026-10-24 | checkpoint 2026-10-24: HIGH 5a + 5b closed (atomic graph save + MCP boot kill handles), release blockers gone |
| dc73b6e | 2026-10-24 | checkpoint 2026-10-24: full sweep, 10 fixes, release hold |
| 68bc115 | 2026-10-24 | checkpoint 2026-10-24: review + freshness fixes + release call |

Working tree composition (54 untracked, 0 tracked changes):

- **46 scratch files** at root named `_*`: 34 `.py`, 6 `.md`, 5 `.txt`, 1 `.sh` (`_commit_rebind.sh`). No `_*.ps1` in git status (four `_logo_audit*.ps1` and `_search*.ps1` exist on disk but are matched by the `.gitignore` `motion_*.ps1`-adjacent rules only in part — see note below).
- **6 untracked validation artifacts**: `validation/build-exe-subpath-gate.out`, `validation/gate-followups.out`, `validation/gate-item8-9a-9b.out`, `validation/gate-item9-block.out`, `validation/repro-compact-fixed.ts`, `validation/repro-compact-orphan.ts`
- **1 untracked scratch dir**: `validation/scratch-rebind/`
- **1 untracked agent-state dir**: `.perch/` (`memory/`, `rules/`, `mcp.json`, `PERCH.md`, all 2026-10-27 18:30)

> Note on `.ps1`: `_logo_audit.ps1`, `_logo_audit2/3/4.ps1`, `_search.ps1`, `_search2.ps1` are present on disk but do **not** appear in `git status`; root `.gitignore` has `motion_*.ps1` and `signing_password*.txt` rules but nothing matching `_*.ps1`, so the reason they are absent was not determined in this pass (likely an ignored pattern reviewed only partially). Counted here as on-disk scratch, not as repo entries.

### Sub-repo — `C:\Users\pc\Desktop\BlackRose\cline\blackrose`

| Field | Value |
|---|---|
| Branch | `main` |
| HEAD | `80dc2c354886079b74434cd8ead16736f60c3d72` |
| HEAD subject | fix: L6 skill slug collision + L7 xlsx numeric sort + L8 session auto-compact |
| `git describe` | `v0.10.2-27-g80dc2c3` (27 commits past the v0.10.2 tag) |
| Modified/added/deleted tracked files | **0** |
| Untracked (non-ignored) entries | **0** |
| Tags | 7; latest `v0.10.2` (2026-10-26) |

`validation/` in this repo is gitignored (`.gitignore:20: validation/`), which is why log files exist on disk while `git status` reports clean. 0 tracked files under `validation/`.

Last 12 commits:

| SHA | Date | Subject |
|---|---|---|
| 80dc2c3 | 2026-10-27 | fix: L6 skill slug collision + L7 xlsx numeric sort + L8 session auto-compact |
| 6b57a34 | 2026-10-27 | fix: M9 fatal key handling - treat as key failure + rotate instead of pool-wide abort; M7 resume session fix - loadLatestSession sorts by updated desc |
| c564173 | 2026-10-27 | fix: audit M6 - exhausted schedule run backs off and disables after 5 resumes; runner.ts tracks resumeCount, sets retryAfter via nextRetryAfter, disables at 5 (same policy as throw path); schedule.ts adds resumeCount field; regression test walks 5 exhausted runs then verifies disabled; tsc clean, audit-fixes 12/12 |
| 53f596b | 2026-10-27 | feat: retrieval eval gate - extract RETRIEVAL_EVAL_DOCS/QUERIES from knowledge_eval into exported constants (12 docs / 20 pairs), add blocking gate test; register retrieval-eval.test.ts in npm test |
| 87e04fb | 2026-10-26 | docs: 2026-10-26 tier-4 block - release follow-ups closed (44e09df..15b8993) |
| 15b8993 | 2026-10-26 | fix: every hand-rolled atomic writer now goes through core/atomicFile.ts (release follow-up) |
| 8afe45b | 2026-10-26 | fix: the SSRF guard's validated IPs are pinned to the connect - DNS rebinding is dead (release follow-up) |
| 2786e3a | 2026-10-26 | fix: a self-exited MCP child stops being advertised as connected (liveConns stale-entry hygiene) |
| 44e09df | 2026-10-26 | fix: subpath node: specifiers can no longer reach the bundle; 46 latent assert imports converted |
| 140ec5f | 2026-10-26 | docs: 2026-10-26 tier-3 block - NEXT WORK 8, 9, 10 closed (321ff57..c1df5d2) |
| c1df5d2 | 2026-10-26 | fix: one persisted vector index = one vector space - no mixed 3072/256-d index on disk (NEXT WORK item 9) |
| bbd5523 | 2026-10-26 | fix: /compact cannot leave an orphan tool_result at the head (NEXT WORK item 9) |

---

## 2. Is there uncommitted real source work?

**No, in both repos.**

- Root: only scratch `_*` files (46), `.perch/` agent state, and validation evidence logs. No tracked file is modified, so nothing under version control is half-done.
- Sub-repo: `git status` is completely empty for tracked and non-ignored untracked content. All source work is committed; HEAD is 27 commits past the release tag.

Caveat worth flagging: the sub-repo being clean means the **working tree matches HEAD**, not that HEAD is verified. The newest audit trail (`validation/repro-m9-fatal-retry.ts`, 2026-10-27 19:09) asserts that commit `6b57a34` (the M9 fatal-key fix, 3 commits back) is defective — see §5.

---

## 3. Tags / version

| Repo | Latest tag | Tag date | Tags total |
|---|---|---|---|
| Root | — (none) | — | 0 |
| Sub-repo | `v0.10.2` | 2026-10-26 | 7 (`v0.9.27`, `v0.9.30`, `v0.9.31`, `v0.10.0`, `v0.10.1`, `v0.10.2`, +1) |

`cline/blackrose/package.json` → `"version": "0.10.2"`, matching the latest tag. `git describe` = `v0.10.2-27-g80dc2c3`: the tree is **27 commits and one day ahead** of the version string, so `0.10.2` no longer describes HEAD.

---

## 4. Build artifacts

`dist/` and `dist-build/` exist but hold the **JS bundle**, not an installer:

| Path | Content | Timestamp |
|---|---|---|
| `dist/` | `blackrose.mjs` 1,750,732 B (~1.67 MB), `BlackRose.cmd`, course `.txt` data files | 2026-10-26 18:38 |
| `dist-build/` | `tsc` emit of `src/` (11 dirs + test/smoke `.js`) | 2026-10-26 18:38:34–18:38:38 |

Windows binaries and installer (Tauri release output, outside `dist*`):

| Artifact | Size | Timestamp |
|---|---|---|
| `desktop/tauri/target/release/bundle/nsis/BlackRose_0.10.2_x64-setup.exe` | 24.69 MB | 2026-10-26 12:01 |
| `desktop/tauri/target/release/BlackRose.exe` | 5.86 MB | 2026-10-26 12:01 |
| `desktop/tauri/target/release/deps/blackrose_desktop.exe` | 5.86 MB | 2026-10-26 12:01 |
| `desktop/tauri/node/node.exe` (bundled runtime) | 89.05 MB | 2026-10-21 17:19 |
| `validation/dl-0101/BlackRose_0.10.1_x64-setup.exe` | 24.72 MB | 2026-10-20 19:26 (previous release, download check) |
| `desktop/tauri/target/release/bundle/nsis/BlackRose_0.10.1_x64-setup.exe` | 24.72 MB | 2026-10-20 18:14 |
| `desktop/tauri/target/release/bundle/nsis/BlackRose_0.10.0_x64-setup.exe` | 24.69 MB | 2026-10-19 13:58 |

**Freshness verdict:** the v0.10.2 installer (2026-10-26 12:01) predates both the `dist/` bundle rebuild (18:38 same day) and every commit from `44e09df` onward, including all four 2026-10-27 commits. It is the shipped release binary, **not** a build of HEAD.

No `scripts/` directory exists at repo root. `scripts/build-exe.ts` exists inside the sub-repo and is what produced `dist-build` + the smoke gate. No publish output found under root `validation/` other than the release download folders already gitignored (`validation/release-repo/`, `validation/release-0.8.1/`, `validation/rel029-download/`, `validation/x929/`, `validation/x929-new/`).

---

## 5. Recent validation logs

### Sub-repo `cline/blackrose/validation` — 10 newest

| File | Size | Timestamp |
|---|---|---|
| `repro-m9-fatal-retry.ts` | 2.6 KB | 2026-10-27 19:09:15 |
| `gate-small-tests.out` | 65.1 KB | 2026-10-26 14:59:22 |
| `gate-small-smoke.out` | 49.2 KB | 2026-10-26 14:58:11 |
| `gate-undo2-tests.out` | 64.9 KB | 2026-10-26 14:56:01 |
| `gate-undo2-smoke.out` | 49.2 KB | 2026-10-26 14:54:43 |
| `gate-undo-tests.out` | 64.9 KB | 2026-10-26 14:50:41 |
| `gate-undo-smoke.out` | 49.2 KB | 2026-10-26 14:49:37 |
| `gate-atomic-tests.out` | 64.7 KB | 2026-10-26 14:42:35 |
| `gate-atomic-smoke.out` | 49.2 KB | 2026-10-26 14:41:10 |
| `gate-item7-tests.out` | 64.2 KB | 2026-10-26 14:37:10 |

Newest 3, content:

**`repro-m9-fatal-retry.ts`** (not a log — a repro script, the newest artifact in the tree):
- Head: `Repro: M9 "fatal" handling (commit 6b57a34).` Setup = 2-key embed pool, key #0 answers HTTP 400 (fatal), key #1 healthy. Expected per the fix's stated intent ("treat as key failure + rotate"): key #0 tried once, then key #1 → 2 fetch calls.
- Head continues: `Actual (the fix used 'continue' inside the inner retry loop, not 'break')`.
- Tail: exits 1 and prints `REPRODUCED: fatal key retried Nx, healthy key tried Mx` when key #0 is tried more than once; otherwise prints `OK: fatal key tried once, rotation to the healthy key happened`.
- No PASS/FAIL line: it is an unexecuted (or unrecorded) repro, so its claim is **unverified by any log**.

**`gate-small-tests.out`**:
- Head: `[vectors] not saving: br-hash-v1 fallback vectors would overwrite the real index...` then `✔ a real-backend embed clears unsafeFallback and saves again (H3)`.
- Tail: `ℹ tests 398 / ℹ suites 0 / ℹ pass 398 / ℹ fail 0 / ℹ cancelled 0 / ℹ skipped 0 / ℹ todo 0 / ℹ duration_ms 69980.9868`.
- Verdict: **398/398 pass, 0 fail** — green.

**`gate-small-smoke.out`**:
- Head: `↪ 2 of 3 route(s) active (skipped: this_route_does_not_exist)`, then `PASS — loop finished with a final text`.
- Tail: `PASS — bookmarklet: the shipped code is a single self-contained javascript: URL that parses`, `PASS — the install doc and the installer script ship with the endpoint`, `SMOKE TEST PASSED`.
- Verdict: **SMOKE TEST PASSED** — green.

### Root `validation` — 10 newest

| File | Size | Timestamp |
|---|---|---|
| `gate-followups.out` | 3.6 KB | 2026-10-26 22:31:53 |
| `build-exe-subpath-gate.out` | 2.2 KB | 2026-10-26 18:39:27 |
| `scratch-rebind/fix-demo.mjs` | 3.0 KB | 2026-10-26 18:31:19 |
| `scratch-rebind/br-rebind-NLNrFO/know…` | 0.8 KB | 2026-10-26 18:30:18 |
| `scratch-rebind/br-rebind-NLNrFO/know…` | 0.5 KB | 2026-10-26 18:30:18 |
| `scratch-rebind/br-rebind-NLNrFO/vect…` | 1.5 KB | 2026-10-26 18:30:18 |
| `scratch-rebind/br-rebind-NLNrFO/know…` | 0.2 KB | 2026-10-26 18:30:18 |
| `scratch-rebind/repro.mjs` | 3.2 KB | 2026-10-26 18:30:03 |
| `scratch-rebind/probe.mjs` | 0.7 KB | 2026-10-26 18:29:24 |
| `gate-item9-block.out` | 3.4 KB | 2026-10-26 17:59:08 |

Newest 3 logs, content:

**`gate-followups.out`** (2026-10-26 22:31:53):
- Head: `GATE START 2026-10-26T22:29:34` / `> node node_modules/typescript/bin/tsc --noEmit` / then `PASS — key rotation: when every key fails the error names the provider and both keys`.
- Body: 18 `PASS —` lines, ending `PASS — vault: a tampered vault file fails closed instead of returning keys`, then `SMOKE TEST PASSED`.
- Tail: a **truncated `ERR_ASSERTION` stack fragment** (`actual: false, expected: true, operator: '=='`) with no test-name header, then `CHECKPOINT INTEGRITY: PASS` and `GATE END 10/26/2026 22:31:53`.
- Verdict: **mixed / not a clean record.** No `FAIL` line and smoke passed, but an unattributed assertion failure is stitched into the log, so this file cannot be read as an unqualified green.

**`build-exe-subpath-gate.out`** (2026-10-26 18:39:27):
- Head: `BUILD START 2026-10-26T18:38:25` / `> blackrose@0.10.2 build:exe` / `> node scripts/build-exe.ts` / `tsc emit → …\dist-build`.
- Tail: `PASS — macro_record save builds an ordinary runnable skill (failed step marked ✗)` then **`SMOKE TEST FAILED`**, then `GATE END 10/26/2026 18:39:27`.
- Verdict: **FAILED.** This is the gate behind the 18:38 `dist/` bundle. It was superseded the same evening by `gate-followups.out` (`SMOKE TEST PASSED`, 22:31), but no later exe-rebuild gate exists.

**`gate-item9-block.out`** (2026-10-26 17:59:08):
- Head: `GATE START 2026-10-26T17:56:39` / tsc line / `PASS — key rotation…`.
- Tail: `ℹ todo 0` / `ℹ duration_ms 55770.9836` / `GATE END 10/26/2026 17:59:08`. No `SMOKE TEST` line.
- Verdict: green on the tsc + test phase (no failure line).

---

## 6. `npx tsc --noEmit` in `cline/blackrose`

**PASSES — 0 errors.**

Command run (read-only, `noEmit` is already set in `tsconfig.json`):

```
cd C:\Users\pc\Desktop\BlackRose\cline\blackrose
npx tsc --noEmit
```

Observed:
- Exit code `0`, **zero diagnostic lines** on stdout/stderr (no `error TS…` lines).
- TypeScript version: `5.9.3`.
- Confirmed the check was not an empty program: `npx tsc --noEmit --listFiles` lists **178 files under `/src/`** (355 total entries incl. 177 `.d.ts`); `tsconfig.json` has `"include": ["src"]`, `strict: true`, `module: nodenext`, `allowImportingTsExtensions: true`.
- Error count: **0**.

Not run (explicitly excluded by the brief): `npm test`, the full suite, the `gate-*` scripts, and any build. Test-suite status is therefore only known from the historical logs in §5 (398/398 in `gate-small-tests.out`, dated 2026-10-26, i.e. before the four 2026-10-27 commits).

---

## Reproduction commands

All read-only:

```powershell
# root
cd C:\Users\pc\Desktop\BlackRose
git rev-parse --abbrev-ref HEAD; git rev-parse HEAD; git log -1 --pretty=%s
git log -12 --date=short --pretty=format:"%h|%ad|%s"
git status --porcelain --untracked-files=no    # 0 lines = no tracked changes
git status --short                              # 54 untracked
git tag                                          # empty

# sub-repo
cd C:\Users\pc\Desktop\BlackRose\cline\blackrose
git rev-parse --abbrev-ref HEAD; git rev-parse HEAD
git describe --tags                              # v0.10.2-27-g80dc2c3
git status --short                               # empty
git tag --sort=-creatordate | Select-Object -First 1
node -p "require('./package.json').version"      # 0.10.2
git check-ignore -v validation                   # .gitignore:20

# type check
npx tsc --noEmit; echo $LASTEXITCODE             # 0, no output
```

## Summary verdict

| Question | Answer |
|---|---|
| Root clean or dirty? | **Tracked-clean, untracked-noisy.** 0 tracked changes; 54 untracked (46 scratch `_*`, `.perch/`, 6 validation artifacts, 1 scratch dir). |
| Sub-repo clean or dirty? | **Clean.** 0 tracked changes, 0 non-ignored untracked entries. |
| Real uncommitted source work? | **None in either repo.** |
| Version | Sub-repo `0.10.2` = tag `v0.10.2`, but HEAD is 27 commits ahead → version string lags HEAD. Root has no tags. |
| Build artifacts current? | **No.** Newest exe/installer is 2026-10-26 12:01 (v0.10.2 release); `dist/` is 2026-10-26 18:38; HEAD is 2026-10-27. No artifact built from HEAD. |
| tsc | **Passes, 0 errors**, 178 src files, TS 5.9.3. |
| Loose ends | `build-exe-subpath-gate.out` = SMOKE TEST FAILED (18:39, later superseded); `gate-followups.out` contains an unattributed `ERR_ASSERTION`; `repro-m9-fatal-retry.ts` claims a live defect in `6b57a34` with no executed evidence. |
