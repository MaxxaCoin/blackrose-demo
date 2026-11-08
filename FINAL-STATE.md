BLACKROSE v0.11.6 — FULL PROJECT STATUS (v0.11.6 RELEASED 2026-11-06, RELEASE PIPELINE REPAIRED 2026-11-07; before that: re-audited 2026-11-03, v0.11.4/0.11.5 RELEASED 2026-11-04, AKI AUDITED+FIXED 2026-11-04)

VERIFICATION PASS (2026-11-08, see BLACKROSE_CHECKPOINT.txt newest block for detail):
  - Audited the 2026-11-08 P1+P2 planner/reflect commit (8cfeec5) and the
    uncommitted trace/eval harness; fixed 3 defects in the harness (test
    arithmetic that could never pass, a fail-open torn write on the
    thresholds file, a dead isError ternary) and wired the harness into
    the REPL, Telegram and web UI hosts so real runs are traced.
  - Gates on HEAD: typecheck 0; npm test 513/513; scan:secrets + scan:history
    clean; verify:checkpoint PASS. Release re-verified LIVE: endpoint 200
    advertising 0.11.6, installer HEAD 200 at 25,981,292 bytes, tag on the
    bump commit, both repos' claims held.


RELEASE PIPELINE REPAIRED (2026-11-07, auditing the previous agents' work):
  1. STALE RELEASE NOTES: the published v0.11.6 body and its latest.json
     carried 0.11.4-era text — scripts/sign-release.ps1 still held a
     hardcoded $notes literal from that release. make-latest-json.ps1 now
     derives notes from docs/RELEASE-<ver>.md (first non-empty line) for
     EVERY caller (sign-release, build-desktop, deploy-run — which never
     passed the then-mandatory -Notes and would have prompted mid-pipeline)
     and refuses notes that do not mention the version being built; a
     missing doc fails the build. GitHub body re-issued; only the
     latest.json asset was replaced (installer/.sig digests untouched).
  2. TAG ON THE PRE-BUMP COMMIT: the version bump had been left uncommitted
     while the release published, so remote tag v0.11.6 sat on 927d8fa.
     Bump committed (48d291c), tag deleted and re-pushed onto it;
     origin/main == HEAD (0 0).
  3. VACUOUS CHECKPOINT GUARD: verify-checkpoint.ts COPIES resolved two of
     three paths to the SAME file (nested layout) and the outer copy had
     been deleted with the source tree (b20a200) — the two-copies-are-byte-
     identical gate hashed one file twice and passed with ONE copy on disk.
     Paths deduplicated by resolved path (missing second copy FAILs);
     outer copy restored, committed 3e6727e and pushed — outer repo master
     in sync (0 0; the two earlier local-only commits b20a200/788dd5f went
     with it).
  - 3 fail-closed regression tests appended to src/audit-fixes.test.ts,
    verified failing against pre-fix code (stash both fixes -> 2 fail / 1 pass).
  - Other doc repairs: docs/08-SESSION-HANDOFF.md refreshed (was stale at
    2026-10-26); checkpoint gained the 2026-11-07 block (0.11.2..0.11.6).

RELEASED v0.11.6 (2026-11-06) — three audit passes, 29 defects fixed:
  - AUDITS: knowledge-ingest D1-D11 (e2efb09, 2026-11-04, detailed below) +
    whole-project D1-D6 (1969bb9) + Telegram-companion 12 defects
    (927d8fa) — all three ship tests that fail against the old code where
    the behaviour is observable.
  - chain: 2490e5c → e2efb09 → 1969bb9 → 927d8fa → 54b1446 (repairs) →
    48d291c (bump); tag v0.11.6 → 48d291c; pushed, 0 0.
  - BINARY: MaxxaCoin/BlackRose release 436762536, published, latest, 3
    assets: BlackRose_0.11.6_x64-setup.exe (25,981,292 bytes, SHA256
    5EBDACFA992133AF159B6E0A5E34097F163E04550B6CC2DBAADA0C4204011682),
    .sig (420 bytes), latest.json (753 bytes, notes from the release doc).
  - SOURCE: MaxxaCoin/blackrose-source release v0.11.6 (notes-only, body =
    docs/RELEASE-0.11.6.md).
  - VERIFIED 2026-11-07: endpoint HTTP 200 advertising 0.11.6, notes ==
    docs/RELEASE-0.11.6.md headline, no BOM, signature == disk .sig;
    installer HEAD 200 at exactly 25,981,292 bytes.
  - gates at tag: typecheck 0; npm test 487/487 (484 at publish + 3
    release-pipeline guard tests); scan:secrets/scan:history clean;
    verify:checkpoint PASS over two byte-identical copies.

WHOLE-PROJECT AUDIT (2026-11-06, 1969bb9) — 6 defects D1-D6, ALL FIXED:
  D1 scheduler stop() only set a flag, so an in-flight tick drained its due
    list and ran every remaining mission as a full agent run (11+ minutes
    observed after exit) — now aborts via AbortController, re-checks
    stopped between missions, aborted run saved INTERRUPTED.
  D2 stop landing on an open approval dialog let a late Allow execute for a
    cancelled run — the stop check now repeats after the dialog; the web
    run host threads the abort (Stop or client-disconnect settles pending
    dialogs DENIED, tools see ctx.signal).
  D3 the UI shell and its script/style assets required an Authorization
    header a browser navigation cannot carry (the token arrives as
    #token=) — shell served ungated; every /api/* route still gated.
  D4 POST /api/custom_tools/remove uncapped -> 4 KB like its siblings.
  D5 conversation map 50-entry cap not enforced on every write path -> now.
  D6 pendingApprovals module-scoped -> per-instance (one server instance
    could settle another's dialogs).

TELEGRAM-COMPANION AUDIT (2026-11-06, 927d8fa) — 12 defects T1-T8/N1-N6:
  T1 the long poll ran handlers inline, so an approval raised during a run
    parked until TTL and then denied, and /stop was unreachable while a
    run held the loop — now confirmed at receipt and drained by one serial
    FIFO, with approval taps and /stop //panic on bypass lanes.
  T2 requestOwnerApproval sent a dead card with no live watch loop,
    ignored console trust, and registered pending after the send — now
    refuses instantly, honours BLACKROSE_APPROVE=all, registers first.
  N1 /trust promised "companion tools run without asking" but was never
    consulted — companionCtx/companionAskApproval honour it for companion
    ORIGINS only (agent-tool and REPL asks stay gated;
    requestOwnerApprovalDetailed and /run untouched).
  T3 /restart reported "Companion stopped." while stopping nothing ->
    refuses honestly, help text corrected.
  T5 /knowledge add <url> had no url keyword (bare URL -> learn_file
    ENOENT throw), dropped isError, defaulted missing args to '.' ->
    learn_url routing, isError carried, throws become answers.
  T6 tgChat had no try/finally — a throwing run stacked the typing
    heartbeat and leaked the controller -> cleanup on every exit path.
  T7 a transport error lost the reply entirely and any non-5xx poisoned
    the capability cache (one 429 downgraded all later sends) -> fall
    through to the classic rungs; only 400/404/405 cached.
  T8 /goal checklist posts fired unordered (double posts, out-of-order
    edits) -> one bounded FIFO poster with a dead flag.
  N2 long poll had no deadline — a half-open socket parked the watch while
    the doctor said "watch ON" -> 45 s deadline with a named diagnosis.
  N4 approval TTL timers were ref'd (held the event loop after /exit) ->
    unref'd.
  N5 failed replies were awaited and discarded -> logged via onEvent.
  N6 runOnce vs loop could issue concurrent getUpdates (Telegram 409) ->
    one shared poll lock.
  HELD for the owner: T4 (pairing-code owner binding).

AKI AUDIT + FIXES (2026-11-04) — knowledge-ingest subsystem, 11 defects, ALL FIXED:
  committed e2efb09, pushed. typecheck 0 errors; npm test 458/458
  (was 451 — +7 pinning tests). RELEASED in v0.11.6 (2026-11-06).
  D11 (worst): a bridge re-push of identical content force-demoted
    owner-verified knowledge. knowledge_verify writes `verified` ONLY to the
    knowledge JSON, while both bridge routes stamped verified=false +
    agent='bridge' on every item — so ingestItem rebuilt meta from the caller
    and wiped the owner's verification, though docs promise demotion is
    owner-only. FIX: engine reads the prior record AND the live knowledge
    JSON before building meta; omitted fields are inherited; verified/agent
    are preserved on same-content re-ingests unless explicitly passed; new or
    changed content starts unverified at the surface identity (new
    `IngestSource.identity`: 'bridge' from token, 'cli' from argv, 'agent'
    default; routes no longer force agent/verified). Explicit demote still
    honored; escalation impossible (body agent/verified never parsed).
  D1 howto was DEAD (declared knowledge.ts, never read in any commit, though
    design/checklist claim it) -> implemented end-to-end: tool schema+run,
    meta, front-matter record, knowledge JSON, knowledge_search hit line,
    knowledge_get header, bridge parseIngestBody + client type; preserved on
    re-ingests that omit it.
  D2 sameMeta compared only agent+verified -> confidence/tags/summary/
    staleAfter/howto edits reported 'unchanged' while rewriting the record.
    Now compares every mutable field (never ts).
  D3 readFrontMatterHeader could not parse the multi-line tags list; a tag
    containing ': ' corrupted the header -> bullet folding + every header
    value written single-line (newline in summary/howto/source can no longer
    truncate the header).
  D4 trustMultiplier (extracted, exported, injectable `now`) omitted the
    legacy user x1.1 boost that knowledge_get and the docs both promise
    ("legacy = user-authored @0.5") -> `meta?.agent ?? 'user'`.
  D5 confidence had no NaN guard (staleAfter did) -> Number.isFinite, fall
    back to inherited value else 0.5; JSON null / front-matter NaN gone.
  D6 non-array tags crashed frontMatter; Boolean("false") self-verified at
    the tool layer -> tags normalized engine-side, verified strict boolean
    at BOTH tool and engine layers.
  D7 knowledge_ingest schema missing staleAfter (run already accepted it)
    and howto -> both declared.
  D8 parseIngestBody spread staleAfter twice -> once.
  D9 doc step 5 still described the retired hybridRank probe (which PRUNES
    and SAVES the store, deleting other docs' vectors) -> rewritten around
    the side-effect-free disk read-back, with why-not-hybridRank.
  D10 doc test counts said 12/13; actual at audit 15/15 -> now 21/16.
  docs/10-AGENT-INGEST.md updated: engine steps 3/5, trust table (+howto,
    staleAfter rows, non-finite confidence), legacy note, bridge preserve-
    rule wording, CLI identity wording, tool example (+howto, staleAfter).
  NEW TESTS (7): metadata-change matrix + settle-to-unchanged + preserve-
    on-omit; NaN confidence; loose caller types (string verified / non-array
    tags); verification preserve/reset/explicit-demote matrix; howto
    end-to-end (tool->JSON->record->knowledge_get); trustMultiplier weight
    table incl. legacy; bridge re-push cannot demote owner-verified knowledge.

RELEASED v0.11.5 (2026-11-04) — fixes the update checker:
  BUG: v0.11.4 was published with ONLY the installer attached. The updater
  endpoint releases/latest/download/latest.json serves an asset NAMED
  latest.json from whichever release is Latest, so once v0.11.4 became Latest
  the endpoint returned GitHub's 404 page -> "update check failed: Could not
  fetch a valid release JSON from the remote" for every installed client.
  (v0.11.2/0.11.3 had shipped setup.exe + .sig + latest.json; 0.11.4 dropped
  two of the three.) Also backfilled latest.json + .sig onto v0.11.4 so the
  endpoint was restored immediately.
  FIX: v0.11.5 published with ALL THREE assets. scripts/latest.json points at
  the v0.11.5 installer with its fresh updater signature.
  - committed ea48702; tagged v0.11.5; pushed.
  - SOURCE: MaxxaCoin/blackrose-source/releases/tag/v0.11.5
  - BINARY: MaxxaCoin/BlackRose/releases/tag/v0.11.5 (published, not draft)
    assets: BlackRose_0.11.5_x64-setup.exe (25,968,117 bytes, SHA256
    9F532088EC133735978D870C1E66ED22EE251DD5F218FB854BE4A8C1A6DE1D45) +
    .sig + latest.json.
  - VERIFIED: endpoint HTTP 200, valid JSON advertising 0.11.5, signature
    present; installer download HTTP 200, length matches build exactly.
  - gates: typecheck 0 errors; npm test 451/451; clean build (dist +
    dist-build wiped, BLACKROSE_RELEASE=1 signed build).

RELEASED v0.11.4 (2026-11-04) — clean signed build, both surfaces live:
  - version bumped 0.11.3 -> 0.11.4 in package.json / tauri.conf.json /
    Cargo.toml (+Cargo.lock); scripts/latest.json updated with the fresh
    updater signature; committed 51249b9; tagged v0.11.4; pushed.
  - SOURCE: https://github.com/MaxxaCoin/blackrose-source/releases/tag/v0.11.4
    (tag v0.11.4 -> 51249b9, notes docs/RELEASE-0.11.4.md).
  - BINARY: https://github.com/MaxxaCoin/BlackRose/releases/tag/v0.11.4
    signed NSIS installer BlackRose_0.11.4_x64-setup.exe (25,975,944 bytes,
    SHA256 9DB493D3EF387797B07E7099D7998A888AFD9F5B9E572DD6C30CA824DE6640F5),
    published (not draft), asset attached.
  - download URL in latest.json verified HTTP 200, length matches — the
    auto-updater points at a live asset.
  - clean build: dist + dist-build wiped first; build:exe then build:desktop
    (BLACKROSE_RELEASE=1, key ~/.tauri/blackrose.key, password from
    signpass.txt); cargo release build + NSIS both green.

WHY A RE-AUDIT: the work was done across multiple agents/AIs, so every claim
was re-verified against actual code rather than trusted. Where the checklist
disagreed with the code, the CODE won and the row was corrected.

SOURCE COMMIT CHAIN (inner cline/blackrose, main):
  base  246d27f (original audit start)
  → 0fe9ff6  audit H5/H6/M1/M3/M4/M5/M6/M7/M11/M12 + slug-fallout test fixes
  → 52ea54b audit M8 (approval TTL settles promise)
  → 0e49855 audit M9 guard + checklist strikes
  → 861c932 audit M10 (body-timeout kept active)
  → fb478f9 audit L3 (mastery default) + L4 (skills validate)
  → a5ffca7 hygiene (.gitignore scratch + checklist strikes)
  → 91f91de fix M9 duplicate forgetToken call (full-source scan)
  → b8b4be5 re-audit: M1 completed (all 4 key writers), M10 timer leak fixed
  → dbaf7a7/8fdcf7c re-audit: L2 epoch approval ids, L5 atomic writes,
                    L6 scheduler latch guard, strike M3/L1/L2/L5/L6
  → 3248eea re-audit: M2 allTime accumulator, budget test nesting fix,
            strike D1-D5 (D4/D6 verified genuinely open)
  HEAD c4e247e — 14 commits ahead of audit start; working tree CLEAN

KEY RE-AUDIT CORRECTIONS (checklist said one thing, code said another):
  M3  PRE-FIXED by 15b8993 (ancestor of audit base) — savePolicies was already
      atomic. The row's "bare fs.writeFileSync" claim was stale.
  D1  PRE-FIXED by 1e6e1b7 — the contradictory sentence no longer exists in
      docs/08-SESSION-HANDOFF.md.
  D2  PRE-FIXED by 1e6e1b7 — DONE markers already credit 9c2c01a.
  M12 only TWO runAgent calls exist in runGoal (row said "three"); both pass
      signal. Row text corrected.
  M10 first fix leaked the abort timer; re-fixed by wrapping text/json/
      arrayBuffer so the deadline covers the body and clears on settle.

AUDIT CHECKLIST (docs/07-BUILD-CHECKLIST.md) — ALL 30 ROWS RESOLVED:
  H1-H6  [x] all fixed
  M1-M12 [x] all fixed (M2 via allTime accumulator, committed 3248eea)
  L1-L6  [x] all fixed (L3/L4 pre-existing correct)
  D1,D2,D3,D5 [x] pre-fixed / fixed and verified this pass
  D4 [x] RESOLVED this pass — build:exe now injects BlackRose.exe as an
      RT_RCDATA resource named NODE_SEA_BLOB via the Win32 resource API
      (scripts/sea-inject.ps1), burns the SEA sentinel fuse
      (scripts/sea-fuse.cjs), and uses a thin CJS wrapper entry point
      (dist/blackrose-sea.cjs) since Node SEA runs its entry as CommonJS.
      Verified: dist/BlackRose.exe (93.6 MB) runs --doctor end-to-end.
      Committed c4e247e. Not a code defect — was a wrong injection route
      (objcopy PE sections are invisible to node's FindResource lookup on PE).
  D6 [x] RESOLVED — all source tags present. Backfilled v0.11.2 (64e17b7) and
     v0.11.3 (246d27f) on 2026-11-04 (verified: package.json reads 0.11.2 /
     0.11.3 at those commits; both reachable from HEAD), then v0.11.4 (51249b9)
     and v0.11.5 (ea48702) tagged with their releases. `git ls-remote --tags
     origin` now shows v0.11.0 / v0.11.1 / v0.11.2 / v0.11.3 / v0.11.4 /
     v0.11.5 — no provenance gap remains.

VERIFIED GATES (all run against HEAD c4e247e):
  - GATE-TS   (npm run typecheck): PASS — zero errors
  - GATE-TEST (npm test):          451 pass / 0 fail (full suite)
  - GATE-DOCTOR (--doctor):        healthy; real counts; routes probed live
  - GATE-BRIDGE (--bridge):        /health 200; / 401 (fail-closed as designed)
  - GATE-UI   (--ui):              page 200; healthy (correction 2026-11-07:
      the "/api/brain/routes 200" claim was false — no commit ever contained
      that route; real routes are /api/brain/sources|source|graph|health)
  - GATE-SECRETS (scan:secrets):   clean
  - GATE-CHECKPOINT (verify:checkpoint): PASS (all 8 checks)
  - GATE-BUILD (npm run build:exe): PASS — BlackRose.exe (93.6 MB) built and
      validated by running --doctor inside it. D4 resolved.
REGRESSION PROOF FOR M2:
  Reverting src/core/budget.ts to pre-fix and running budget.test.ts makes the
  new "M2: an all cap stays reachable…" test FAIL (1 fail); restoring the fix
  makes it pass. Test pins 20010 > 20005 — the trimmed total (20000) would
  have let the cap through, which is exactly the defect.

DEFECT FOUND IN THE TEST SUITE ITSELF (fixed in 3248eea):
  src/tools/budget.test.ts had an unclosed `test(...)` at line 52. Three later
  tests were silently NESTED inside it and two assertion blocks were stranded
  at end-of-file (they only ran because of the accidental nesting). Tests are
  now properly closed and top-level: 8 tests in that file (was 7).

HYGIENE:
  - .zwork/attachments/ no longer exists; recursive search for signpass.txt /
    oxion_api_key.txt finds 0 files; .zwork/ is gitignored (.gitignore:27)
  - .gitignore covers build-*.txt, start-ui*.bat, upload-*, run-*, minisign,
    test.zip, *.log, exe-upload-log.txt, full-release-*.txt, docs/RELEASE-*.md
  - 5 scratch files accidentally swept into a commit were `git rm --cached`
    (kept on disk, now ignored)
  - REMAINING.md deleted; FINAL-STATE.md (this file) is outer-repo, untracked

NOTES / CAVEATS:
  - Killing the --ui test run also stopped a pre-existing UI instance
    (pid 4852) that held the Telegram watch. The watch re-acquires on next
    launch; no data affected.
  - Scratch files still exist on disk by design (ignored, not deleted).
