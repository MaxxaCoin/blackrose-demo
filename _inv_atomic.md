# Investigation: unifying hand-rolled atomic writers onto src/core/atomicFile.ts

Repo: `C:\Users\pc\Desktop\BlackRose\cline\blackrose` (read-only investigation; src/ untouched).
Helper: `src/core/atomicFile.ts` (commit 2386a9c, 2026-10-26) — `writeFileAtomicSync` / `writeFileAtomic` (async) / `writeFileAtomicAtSync` / `writeFileAtomicAt` (mkdir flavours). Temp name: `${target}.tmp-${process.pid}-${Date.now()}`; fsync; rename; unlink temp on rename failure.

## 1. Definitive list of hand-rolled tmp+rename state-file writers (16 sites / 15 files)

| # | Site | Temp naming | fsync | mkdir | cleanup-on-fail | Notes |
|---|------|-------------|-------|-------|-----------------|-------|
| 1 | memory/vectors.ts:260-276 `saveStore` | pid+**counter** | yes | dirname recursive | rmSync on fail | sibling tmp of `store.path`; JSON compact; `store.dirty=false` after |
| 2 | memory/graph.ts:289-325 `saveGraph` | pid+**counter**, two halves | both temps fsynced **before any rename**; renames sequential | ensureStore | rmSync both on fail | mixed-pair semantics documented (new entities + prior relations) |
| 3 | session/history.ts:105-119 `saveSession` | pid+counter | yes | (dir pre-exists) | rmSync on fail | redacted transcript written here |
| 4 | core/undo.ts:172-194 `writeEntry` | pid+counter | yes | entriesDir recursive | rmSync on fail, rethrow | rollback manifest |
| 5 | tools/schedule.ts:87-101 `saveSchedules` | pid+counter | yes | dirname recursive | rmSync on fail | corrupt-quarantine at :50 on read path |
| 6 | tools/knowledge.ts:124-141 `atomicWriteFileSync` (used at :150, :549, :2029, :2037, :2115) | pid+Date.now | yes | no | **no cleanup** | local duplicate of the helper; no try around rename |
| 7 | core/budget.ts:117-124 `writeLedger` | pid+Date.now | **no** | dataDir | **no cleanup** | corrupt-quarantine lives in `readLedger` :98-112 — independent of write path |
| 8 | core/costmeter.ts:81-86 `writeUsage` | Date.now only | no | no | no | weakest temp name |
| 9 | core/policy.ts:67-75 `savePolicies` | pid only | no | dataDir | no | |
| 10 | core/workflow.ts:140-144 `mutateWorkflows` | pid only | no | caller? load path | no | lock-guarded (spin lock) |
| 11 | core/instanceLock.ts:79-83 `writeOwner` | pid only | no | n/a (dir exists) | no | heartbeat rewrite; half-written lock = false takeover |
| 12 | core/plugins.ts:107-112 `writeRegistry` | fixed `.tmp` | no | dataDir | no | guarded by plugins.lock ('wx') |
| 13 | tools/custom.ts:108-112 `writeDefs` | fixed `.tmp` | no | dataDir | no | lock-guarded |
| 14 | tools/selfimprove.ts:87-91 `saveLedger` | fixed `.tmp` | no | dataDir | no | |
| 15 | mcp/client.ts:366-370 `saveMcpServer` + :378-382 `removeMcpServer` | fixed `.tmp` | no | dataDir | no | two call sites, same body |
| 16 | core/vault.ts:164-170 `writePrivate` | crypto randomBytes(4) | no | n/a | no | **+ hardenAtRest(tmp) BEFORE rename, hardenAtRest(file) after**; Buffer|string; sole write path for keystore (core/keystore.ts:102 writeStoredKeys → writeVault → writePrivate) |

Note: knowledge.ts's helper serves 5 call points (:150, :549, :2029, :2037, :2115), so one swap covers 5 writes.

**Excluded** (rename, but not the tmp+fsync+rename state-writer pattern):
- tools/video.ts:76 — binary yt-dlp.exe download (tmp `${dest}.${pid}.download`, no fsync, has cleanup). Could optionally adopt `writeFileAtomicSync`, but it's binary + integrity-checked, low value.
- backup.ts:72 — backup rotation move, not an atomic write.
- tools/telegram.ts:1908 — download move.
- session/history.ts:55 (corrupt quarantine), :147, :248 (restore moves); tools/schedule.ts:50 and core/budget.ts:110 — corrupt-file quarantine renames (read path).
- Lock files via `openSync(lock,'wx')`: plugins.ts:133, custom.ts:133, keystore.ts:157, budget.ts:212/224 — separate mechanism, out of scope.

**src/tools/office.ts**: no tmp/rename/atomic code at all — the checkpoint's guess is wrong.

## 2. Flavor mapping & gaps

- **Sites 1-6** (vectors, graph-halves, history, undo, schedule, knowledge) already have the strongest flavor: unique temp (pid+counter), fsync, cleanup-on-failure. Map to `writeFileAtomicSync` / `writeFileAtomicAtSync` (vectors/schedule/undo use mkdir → `At` variant; history/graph don't mkdir → plain sync flavour).
- **Sites 7-15** map to sync/At-sync flavours and **gain** fsync and cleanup-on-failure (strict improvements, no test asserts their absence of fsync).
- **Tiny gaps / behavior notes:**
  - Helper temp = pid+Date.now vs pid+counter at sites 1-5: weaker uniqueness. In-process collision needs two writers in the same millisecond; only reachable via the async flavour interleaving between temp-name computation and open. All current sync call sites are unaffected. Worth a note, not a blocker.
  - **vectors.ts**: writes JSON to a sibling tmp then renames — exactly the shared pattern (sibling tmp of `store.path`, fsync, rename, rm on fail, mkdir). Maps 1:1 to `writeFileAtomicAtSync`. Zero behavior change. (The pid+counter-vs-Date.now nuance above is the only delta.)
  - **graph.ts** is the one true mismatch: the helper does write→rename per file, while saveGraph flushes BOTH temps before either rename. Per-half calls would mean a crash after half-1's rename but before half-2's write leaves a mixed pair that today would have stayed fully old. Both states are documented as acceptable (graph.ts:276-286 — loadGraph reads halves independently), but it IS an ordering weakening. Either migrate and document, or leave graph as-is.
  - **vault.ts (16)** cannot move without a hook: it runs `hardenAtRest(tmp)` (icacls ACL) *before* rename and again on the target after. `writeFileAtomicSync` has no pre-rename hook, so unification either changes ACL timing (tiny window with un-ACL'd file) or needs a hook parameter. Flag as behavior-changing; recommend keeping writePrivate as the ACL-aware wrapper (it can still call a future `writeTempSync`+`rename` split if desired).
  - Budget/schedule corrupt-quarantine (`.corrupt-<ts>`) is a read-path concern and stays per-site regardless of the write helper.

## 3. Recommended unification order & regression risk

1. **Fixed-`.tmp` weak sites — lowest risk, biggest gain**: mcp/client.ts ×2, tools/custom.ts, tools/selfimprove.ts, core/plugins.ts, core/costmeter.ts, core/policy.ts, core/workflow.ts. Mechanical swap to `writeFileAtomicAtSync`; gain fsync + cleanup. Risk: low (lock-guarded or single-writer; no test pins their temp names — audit-fixes.test.ts matches `.tmp` substring, still true).
2. **core/budget.ts**: gains fsync+cleanup; keep readLedger quarantine untouched. Risk: low (tools/budget.test.ts pins quarantine, unaffected).
3. **tools/knowledge.ts**: delete local `atomicWriteFileSync`, import shared — the swap also *gains* cleanup-on-failure it currently lacks. Risk: low (5 call points, all covered by kb-ingest/knowledge tests).
4. **core/instanceLock.ts**: gains fsync+cleanup; temp stays pid-unique which is sufficient (one writer per process). Risk: low (instance-lock.test.ts).
5. **Dedupe of the strong sites — near-zero risk**: memory/vectors.ts, session/history.ts, tools/schedule.ts, core/undo.ts. Identical semantics (mkdir where they had it); only temp-name generator changes.
6. **memory/graph.ts — medium**: keep the two-half orchestration, call the helper per half; accept the documented mixed-pair semantics (crash window shifts from "between renames" to "after half-1 rename"). Alternatively leave as-is; cross-file atomicity needs a journal either way.
7. **core/vault.ts — do not unify (or last, with a hook)**: ACL hardening around the rename is not expressible in the current helper; the keystore path is security-sensitive (secrets.test.ts, smoke vault sections). Highest regression risk, least gain (it already has random temp + rename).

## 4. Test strategy

**Existing pins per site:**
- vectors: `memory/vectors.test.ts` (mixed + fallback stores); `audit-fixes.test.ts:199-201` (no `.tmp` debris after completed saves across modules).
- graph: `regression.test.ts:1968,1998` (graph stores); `audit-fixes.test.ts:339-366` (`br-audit-h2*` — mixed-pair/halves resilience).
- schedule: `audit-fixes.test.ts:214-243` (corrupt quarantine + no tmp debris) — schedule has no dedicated test file.
- budget: `tools/budget.test.ts:90-91` + `budget-ledger.test.ts` (quarantine read-path); `smoke.ts:807`.
- policy: `policy.test.ts`; plugins: `tools/plugins.test.ts`; custom: `regression.test.ts:2124`; workflow: `tools/workflow.test.ts`; mcp: `mcp/client.test.ts`; selfimprove: `tools/selfimprove.test.ts`; instanceLock: `instance-lock.test.ts`; undo: `core/undo-gc.test.ts` + smoke.ts:1234; history: `session/redact.test.ts` + smoke sessui; vault/keystore: `tools/secrets.test.ts`.
- Helper itself: `core/atomicFile.test.ts` (round-trip + no debris; failed rename leaves old file + no debris; async mkdir flavour).
- `audit-fixes.test.ts:266-288` monkeypatches renameSync to fail for `.tmp-` sources and asserts no litter — this is the cross-site debris contract; it keeps working after unification (tmp names still contain `.tmp-`).

**One shared test addition that proves the helper contract:** in `core/atomicFile.test.ts`, add an overlapping-writers test — fire several concurrent `writeFileAtomic` (async) calls at the same target in the same process and assert (a) every final read is complete/parseable, (b) no `.tmp-` debris remains. This pins the pid+Date.now temp-uniqueness assumption under async interleaving — the one property the strong sites had (pid+counter) and the helper only asserts implicitly. A failed-async-rename cleanup twin of the existing sync failure test would close the remaining gap.

## Verification trail
- Greps used: `renameSync` (complete — 27 hits, all accounted for above), `writeFileSync(.*fd|openSync(` (complete), `.tmp` (truncated at 100 but cross-checked via the complete renameSync/openSync sets), `copyFileSync.*tmp|writeFile.*tmp|.corrupt` (no new writers).
- office.ts checked directly: no atomic writer.
- keys.ts confirmed to write only through `writeStoredKeys` → `writeVault` → `writePrivate` (core/keys.ts:28,62,142,201,218,437).
