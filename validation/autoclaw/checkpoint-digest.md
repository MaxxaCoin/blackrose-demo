# BlackRose — checkpoint digest (state as of newest block)

Compiled 2026-10-27. Read-only investigation: no existing file was modified; this file and its
directory are new.

## 0. Sources and scope

| Source | Size | Note |
|---|---|---|
| `BLACKROSE_CHECKPOINT.txt` | 3,628 lines | 31 `SESSION` blocks, newest at TOP |
| `_road.md` | 72 lines | roadmap/backlog, last touched 2026-10-19 era |
| `v0930-notes.md` | 8 lines | v0.9.30 release note only (stale, not current state) |

Newest-first block index (line numbers are `BLACKROSE_CHECKPOINT.txt`):

| Block | Lines |
|---|---|
| SESSION 2026-10-26 TIER 4 | 1–77 |
| SESSION 2026-10-26 TIER 3 | 80–158 |
| SESSION 2026-10-26 TIER 2 | 163–227 |
| SESSION 2026-10-26 TIER 1 | 231–286 |
| SESSION 2026-10-26 v0.10.2 PUBLISHED | 290–365 |
| SESSION 2026-10-26 FULL RECHECK (sweep 2) | 369–429 |
| SESSION 2026-10-25 AUDIT OF PREVIOUS AGENT | 433–503 |

---

## 1. The three newest blocks — what was closed

### 1.1 TIER 4 — release follow-ups closed (L1–77)
Scope line: `DATE / TIME: 2026-10-26 tier 4 - release follow-ups closed (44e09df..15b8993)` (L4).

- **Subpath specifiers** (L6–20, `44e09df`): bundler only hoists slash-free `node:x`; 46 occurrences
  (all `node:assert/strict`) converted to `import { strict as assert } from 'node:assert'`.
  `build-exe.ts` gained an emit-time scan. Real build verified: 127 modules, `--check` ok, `--doctor` ok.
- **liveConns hygiene** (L21–33, `2786e3a`): `isConnected` stayed true for a dead child and
  `listServers` advertised `connected:true`; `onDeath` now fires once, every registry path reaps with an
  identity check. Test fails pre-fix.
- **DNS rebinding** (L34–43, `8afe45b`): guard validated one resolution, `net.connect` re-resolved
  (TTL 0 attack). Reproduced live pre-fix; guarded fetch now uses `node:http/https.request` with a
  pinned `lookup` hook. `BLACKROSE_FETCH_TIMEOUT_MS` env-tunable.
- **Atomic writers unified** (L44–60, `15b8993`): 14 sites / 12 modules on `core/atomicFile.ts`;
  two real defects found by the new test (non-unique temp name; Windows EPERM retry) and fixed.
  Deliberate exceptions: `memory/graph` (cross-file ordering) and `core/vault writePrivate`.
- **Gates** (L61–68): tsc 0; smoke PASSED; node:test **427 tests, 0 fail**; scan:secrets 17
  fingerprints each classified as identifier/call/env reference; `verify:checkpoint` PASS.

### 1.2 TIER 3 — NEXT WORK 8, 9, 10 closed (L80–158)
- **Item 8** (L82–92, `321ff57`): one Telegram watch per data dir via `instanceLock` role
  `telegram-watch`; second host gets an inert handle plus a reason; dead-owner takeover by pid check.
- **Item 9, /exit hang** (L93–101, `321ff57`): watch re-issued long polls forever; CLI now stops the
  watch on both exit paths and aborts the pending poll via `AbortController` wired into
  `telegramGetUpdates`.
- **Item 9, bridge timeout** (L100–104, `ac7991d`): `jsonCall` had no timeout; 10-minute ceiling,
  `BLACKROSE_BRIDGE_TIMEOUT_MS`, error names the route.
- **Item 9, /compact orphan** (L105–115, `bbd5523`): re-anchor checked only `role === 'user'`;
  `compactHistory` now drops leading `tool_result` carriers like `trimHistory`. Pre-fix repro exits 1.
- **Item 9, mixed-dim vectors** (L116–123, `c1df5d2`): a stranded re-embed could insert 256-d vectors
  into a 3072-d store; only same-space vectors are cached, `saveStore` drops mismatched length.
- **Item 10** (L130–138): dead `onemin` route removed from `HKCU\Environment` `BLACKROSE_ROUTES`
  (data-side only, no code change). `kilo` also in the chain with no adapter — **left for owner**.
- **Gates** (L140–152): tsc 0; smoke PASSED (4 documented machine-dependent false failures);
  node:test **403/403**; scan:secrets clean. Pushed `321ff57..c1df5d2` (L153).

### 1.3 TIER 2 — NEXT WORK 7, atomic stragglers, undo L1+L2 (L163–227)
- **Item 7, stale sandbox** (L167–177, `cecf5ba`): `apply_change` blind-copied snapshots back and
  destroyed intervening edits. Now records sha256 per file and refuses before spending the test run,
  naming both short hashes; deleted target is not resurrected.
- **Atomic stragglers** (L178–185, `2386a9c`): constitution, mastery, experiment records were the last
  truncate-then-write files; now use the new `src/core/atomicFile.ts`.
- **Undo L1 + L2** (L186–196, `a8575e7`): L1 fixed a blob-GC race (first attempt with a wall-clock
  grace period was rejected by the smoke gate — rule now keys on manifests, not the clock);
  L2 folded the "restored" status write into the result (`statusWriteFailed`).
- **Small batch** (L197–199, `b7f9fb6`): `killTree` on timeout (Windows grandchildren survived
  `child.kill()`); `BLACKROSE_MAX_TURNS=` empty now counts as unset.
- **Tests** (L200–208): **398/398**, seven new. L2 has no direct test — stated in the commit.

---

## 2. Every open / queued item found in the file

Status column is my verification against the repo on 2026-10-27, not the file's own claim.

| # | Item | Source lines | Status I verified |
|---|---|---|---|
| 1 | **Queue rows 137–139**: 137 teach-by-demo adjudication, 138 UI knowledge/graph viewer, 139 UI git/repo panel + undo | L72–73, L156, L427, L501, L571, **L723–724**, L1047, L1104–1105 | **OPEN** — no commit references 137/138/139 |
| 2 | **20-pair retrieval eval gate** before any bulk ingest | L73, L157, L501, L571, **L724**, L1036–1039 (row 151 "STILL PENDING") | **DONE 2026-10-27 — `53f596b`**; checkpoint is stale here (see §5) |
| 3 | **Owner decision — `mini.ts` constitution default** | L74, L725, **L1046** ("OWNER DECISION - ask, do not change silently"); `docs/08-SESSION-HANDOFF.md:245` | **OPEN** — needs owner |
| 4 | **Unguarded `web_fetch`** (`tools/web.ts`, redirect-following, no SSRF guard) | **L39–41** ("FLAGGED, NOT FIXED … needs an owner decision"), L75 | **OPEN** — needs owner |
| 5 | **Audit M8 + L1–L5** (state audit tail) | **L722** ("state-audit M6-M9 and L1-L8"); `cline/blackrose/validation/audit-bugs-state.md:29` ("Still open: M6–M9, L1–L8"), M8 at :312, L1–L5 at :349–377 | **PARTIAL** — M6/M7/M9 + L6/L7/L8 closed 10-27; **M8, L1–L5 still open** (no commits) |
| 6 | **Owner decision — default approval gate not fail-closed** (audit H3) | **L696–701** ("OWNER DECISION if it should be enforced mechanically"); handoff:133 | **OPEN** — behaviour deliberately unchanged |
| 7 | **`kilo` route in env chain, no adapter** — prune or keep | L136–138 | **OPEN** — owner's call, costs a warning row |
| 8 | **Updater private key has a short, guessable password — do NOT rotate casually** | L356–359 | Standing constraint, not a task |
| 9 | Sweep-2 residual LOW list stands unchanged | L349–352, L421–426, L489–492 | OPEN, low severity |
| 10 | Installed-app test-drive | L1196–1198, L1223–1224 | **CLOSED** — 0.10.2 installed via in-app updater (L362) |

Explicit "nothing left" statements: L75–76 "Nothing in the release follow-up list remains open";
L1191 "nothing ungated remains" (roadmap, 10-19).

---

## 3. Release state

- **Published version: 0.10.2** — `cline/blackrose/package.json:3` `"version": "0.10.2"`; block at L290.
- **Signed and payload-verified** (artifacts L322–329, payload L330–334):
  - installer `BlackRose_0.10.2_x64-setup.exe` 25,892,248 B,
    SHA256 `1314FBEB…855E6F`; `.sig` 420 B `784A533D…172D32`; `latest.json` 713 B `C52DF6E1…670AD`.
  - manifest signature equals the `.sig` on disk (checked independently of the build script).
  - payload extracted with 7z; shipped `core/blackrose.mjs` (1,729,792 B) contains every release
    marker and passes `node --check` (L330–334).
- **Live** (L342–348): annotated tag `v0.10.2` on `d484374` pushed to `MaxxaCoin/blackrose-source`;
  assets re-downloaded via gh and re-hashed byte-identical; `releases/latest/download/latest.json`
  serves 0.10.2; installer URL HTTP 200, content-length 25892248.
  https://github.com/MaxxaCoin/BlackRose/releases/tag/v0.10.2
- **Post-release check closed** (L362): installed through in-app "Check for update"; chain closed
  tag → signed assets → live manifest → real update.
- **Gate recipe required before a release** (L335–341, L715–721, L61–68):
  `npx tsc --noEmit` = 0 · `node src/smoke.ts` PASSED · `node --test` all suites 0 fail ·
  `npm run scan:secrets` (every fingerprint classified, zero literal values) ·
  `npm run verify:checkpoint` PASS · bundle `--check` + `--doctor` ·
  then build → draft → verify assets → re-hash → publish `--latest`.
- **Shipped binary does not contain post-release fixes**: `d484374` is an ancestor of `80dc2c3`,
  with **27 commits** between them.

---

## 4. Working conventions a new agent must follow

1. **Checkpoint is APPEND-ONLY, prepend-only** — L1724: "RULE FROM NOW ON: APPEND-ONLY, one line per
   session block, never rewrite the body, and run verify:checkpoint before committing." Root cause
   recorded: line-slicing edits destroyed history three times (`c2853f4`, `efb0316`, `ddc992c`).
2. **Commit messages must state the security-scan verdict truthfully** — L485–487: a commit claiming
   "scan:secrets clean" while the scan exited 1 on 4 classified fingerprints was corrected and recorded
   as an overclaim; "Commit messages must state the scan verdict as it is."
3. **Owner decisions are asked, never taken silently** — L1046: "(OWNER DECISION - ask, do not change
   silently)". Same rule applied to H3 (L701) and `web_fetch` (L41).
4. **Never trust a stale `dist-build/`** — L721; rebuild rather than ship an existing artifact.
5. **Do not ship unreviewed** — L312: when review capacity is missing, "review the riskiest hunks
   yourself before shipping - do not ship unreviewed."
6. **Do not re-open closed findings** — L993 "Those three HIGH groups are CLOSED; do not re-open them";
   L1052 "DO NOT RE-FIX the three closed HIGH adapter groups".
7. **Gates per commit, not once at the end** — L212–217 ("GATES PER COMMIT, NOT ONCE"); one full-gate
   log over the final tree is allowed only when named (L146–147).
8. **Commit message style** (observed across the log): `fix:` / `feat:` / `docs:` / `test:` prefix,
   then the behaviour change and its proof — e.g. `fix: one persisted vector index = one vector space
   - no mixed 3072/256-d index on disk (NEXT WORK item 9)`; docs commits are
   `docs: 2026-10-26 tier-N block - <summary> (<range>)`.
9. **Both repos carry a checkpoint copy** and must stay byte-identical — `verify:checkpoint`
   (L1101, L1257); inner = `cline/blackrose`, outer = workspace root.

---

## 5. DISCREPANCY — the 2026-10-27 work is NOT in the checkpoint

**Finding: the checkpoint file contains no record of the 2026-10-27 session.**

- Grep over the whole file: **zero** hits for `2026-10-27`, `10-27`, `80dc2c3`, `63a4656`.
  (Only `80dc2c3`-adjacent strings such as `79592b2` exist, different commits.)
- The newest content is the **2026-10-26 TIER 4** block (L1–77), and it was added *by* outer commit
  `63a4656` ("checkpoint: 2026-10-26 session wrap-up with audit fixes and handoff notes",
  2026-10-27 17:22:05 +0530, `BLACKROSE_CHECKPOINT.txt | 160 +++++`, insertions only). That commit's
  message says "audit fixes" but its **diff contains only the tier-4 block** — no line about M6/M7/M9
  or L6/L7/L8 appears in the file.
- So the user's pairing is a **cross-repo mix**: `80dc2c3` is an *inner* code commit, `63a4656` is the
  *outer* docs commit that published the 10-26 block.

Actual 2026-10-27 work in `cline/blackrose` (4 commits, all **unpushed**: `rev-list --left-right
--count origin/main...HEAD` = `0  4`):

| Commit | Time (+0530) | Subject | Files |
|---|---|---|---|
| `53f596b` | 06:18:35 | feat: retrieval eval gate — 12 docs / 20 pairs, blocking gate test | `package.json`, `src/tools/knowledge.ts`, `src/tools/retrieval-eval.test.ts` |
| `c564173` | 06:33:32 | fix: audit M6 — exhausted schedule run backs off, disables after 5 resumes | `src/schedule/runner.ts`, `src/tools/schedule.ts`, `src/audit-fixes.test.ts` |
| `6b57a34` | 08:07:18 | fix: M9 fatal key handling + M7 resume session fix | `src/memory/embedder.ts`, `src/session/history.ts` |
| `80dc2c3` | 17:21:51 | fix: L6 skill slug collision + L7 xlsx numeric sort + L8 session auto-compact | `src/index.ts`, `src/memory/xlsx.ts`, `src/skills/skills.ts` |

Consequences (three statements in the checkpoint are now stale):

1. **L73 / L724 "20-pair retrieval eval gate before any bulk ingest"** — already implemented by
   `53f596b`; `src/tools/retrieval-eval.test.ts` exists and is registered in `package.json:15`.
   The gate the file calls "STILL PENDING" (L1037) is green.
2. **L722 "state-audit M6-M9 and L1-L8"** — M6/M7/M9 and L6/L7/L8 are closed; **M8 and L1–L5 are
   still open** (`audit-bugs-state.md:29`, M8 at :312, L1–L5 at :349–377). So the audit tail is
   *not* finished, contrary to a flat reading of "H1-M9 and L6-L8".
3. **Gate bookkeeping** — no gate log exists after `validation/gate-followups.out`
   (2026-10-26 22:31). Commit `c564173` claims "tsc clean, audit-fixes 12/12" in its message, but
   **no full-gate run (smoke / node:test / scan:secrets / verify:checkpoint) is recorded** for the
   10-27 tree.

Structural note: the tier-4 header says it "supersedes the tier-3 block above" (L1) while tier 3 sits
*below* it (L80) — a wording slip, not a content loss; the 160-line diff is pure insertion.

---

## 6. Unverified / open questions (not findings)

- Whether the four 10-27 commits were meant to be pushed before writing a checkpoint block — no
  statement either way exists.
- Whether a full gate run was performed locally on 2026-10-27 without writing a log.
- M8 and L1–L5: no commits found by `git log --grep`; status taken from the audit document, which is
  itself dated 2026-10-24.

## 7. Suggested next step

1. Write the missing `SESSION 2026-10-27` block at the top of the checkpoint, covering
   `53f596b..80dc2c3` and explicitly retiring the retrieval-eval-gate line.
2. Run the full gate recipe on the 10-27 tree and record the log (the file's own convention,
   L212–217), then push the 4 commits.
3. Re-state the audit tail honestly: M8 + L1–L5 open, not "M6-M9/L1-L8".
