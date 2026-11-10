BLACKROSE v0.11.6 — FULL PROJECT STATUS (v0.11.6 RELEASED 2026-11-06, RELEASE PIPELINE REPAIRED 2026-11-07; before that: re-audited 2026-11-03, v0.11.4/0.11.5 RELEASED 2026-11-04, AKI AUDITED+FIXED 2026-11-04)

BUILD QUEUE ITEM SHIPPED (2026-11-10, TRUST MODE COVERS UNATTENDED APPROVALS — see BLACKROSE_CHECKPOINT.txt newest block for detail):
  - Defect (the trust-mode roadmap item): trust was interactive-only.
    `let trustOn` lives in ui/web/server.ts, but the scheduler's
    askApproval (schedule/runner.ts) and the inbox watcher's guard
    (tools/inbox.ts) each built their own fail-closed gate that never saw
    it — with trust ON every unattended run still auto-denied every gated
    tool (soak at read time: 143 denials / 0 granted, firing schedules
    doing silent no-ops), the opposite of "trust mode should allow all the
    permissions".
  - Fix (src/core/trust.ts): a process-wide consent registry of LIVE
    getters — registerTrustSource(fn) + processTrustOn(), fail-closed when
    nothing is registered. server.ts registers trustActive beside
    `let trustOn = false` (the regression one-source-of-truth pin holds
    unchanged); telegram.ts registers consoleTrustOn so
    BLACKROSE_APPROVE=all (already documented as process-wide consent)
    finally reaches unattended surfaces too. No host call site changed, so
    there is no wiring to forget. Every grant writes a transcript line and
    lands in the trace as approval ok:true (denials ok:false), giving
    mine:traces a granted-vs-denied story; trust OFF keeps the exact deny
    line and never-hang behavior.
  - Test: src/trust-unattended.test.ts (5 cases): the REAL /api/trust
    toggle drives a live scheduler both ways, console trust grants, the
    SCHEDULE_APPROVE=all hatch grants under a distinct label (no vacuous
    pass), the registry fails closed, source pins cover both registrations
    and the inbox watcher's guard. Trace approvals asserted as a SET — the
    runId stamp is only second-granular.
  - Gates: typecheck 0; npm test 546/546 (541 baseline + 5 new, smoke
    included); scan:secrets clean (8 staged); scan:history clean (472
    commits, 6.3 MB); verify:checkpoint PASS (sha256 70fc90ac3689). Soak
    left running untouched (it validates the previous build); the new
    wiring takes effect on the next host start.

BUILD QUEUE ITEM SHIPPED (2026-11-10, MINER CROSS-RUN REPETITION — see BLACKROSE_CHECKPOINT.txt newest block for detail):
  - Third fail-open in `npm run mine:traces`, found by reading the 5-hour
    soak's output. "Repeated identical errors" only fired when ONE run
    repeated the same error twice, so a failure recurring on EVERY firing
    never registered: ui_elements.json was missing in 18 SEPARATE runs,
    listed as 18 unrelated "stuck errors", while the repetition section
    read "0 — no adaptation". The report claimed no pattern for the
    clearest pattern there is.
  - Fix (scripts/mine-traces.ts): accumulate tool+error text against a SET
    of runIds (one run hammering an error 12x = ONE run), then report keys
    seen in >= 2 distinct runs under "Same error across runs", sorted by
    run count with the ids for trace_view. The within-run view is kept —
    it answers a different question (didn't adapt inside this run vs
    nobody fixed it between runs). The verdict line counts it too, or it
    would still print "nothing suspicious" with a pattern on screen.
  - Live result: 3 groups — 18 runs missing phase21/ui_elements.json, 3
    missing digital_world_map/discover_models.py, 2 missing
    configs/resource_limits.json.
  - Soak status at read time: ~215 traces / 470 KB over ~5h, 208+ done,
    561 tool calls (4.5% errored), 143 denials / 0 granted, 0
    run_command policies created (3 policy_set attempts all denied — the
    approval gate held). Route tray shows openai1 back to ok, confirming
    the tool-ceiling fix; openai2/oxion still down.
  - Test: src/mine-traces.test.ts (5 cases). Gates: typecheck 0;
    scan:secrets clean (3 staged) + scan:history clean (471 commits);
    verify:checkpoint PASS (sha256 cac25bcb923f), npm test 541/541.

BUILD QUEUE ITEM SHIPPED (2026-11-10, ROUTER TOOL CEILING — see BLACKROSE_CHECKPOINT.txt newest block for detail):
  - Defect found while starting the soak: BlackRose sends 165 tool schemas
    per turn, Groq (route openai1) caps at 128 and answers HTTP 400
    "'tools' : maximum number of items is 128". The router had no notion
    of a tool limit, so it re-sent the SAME oversized request on every
    turn, paid the round trip, and repainted the route tray degraded each
    time — with openai2 (fetch failed) and oxion (HTTP 401) down, that sat
    in the hot path of most turns.
  - Fix (src/llm/router.ts): learn the ceiling from the provider's OWN
    error message, keyed by route name, and skip routes whose cap is below
    the current request's tool count. The skip is a soft preference (if
    nothing fits, try everything — same rule as the known-down skip) and
    is per CALL, not a route kill, so a tool-less request (the planner
    sends none) still reaches the route. No per-vendor table to rot.
  - Test: src/llm/adapters.test.ts pins try-exactly-once, the limit
    surfacing as the fallthrough reason, the next oversized call skipping
    it with no failure notice, and a tool-less call still reaching it.
  - Soak now running: bridge :8787 + --ui :8788 (scheduler pid 3704); the
    bridge host returns before startScheduler so one host cannot do both.
    Miner over live data: 36 runs, done=35 error=1, 80 tool calls, 27
    denials, 7 stuck errors. Owner declined a spend cap (uncapped by
    explicit choice).
  - Gates: typecheck 0; scan:secrets clean (3 staged) + scan:history clean
    (470 commits); verify:checkpoint PASS (sha256 cee3cc34ef7c).

BUILD QUEUE ITEM SHIPPED (2026-11-10, KNOWLEDGE VERIFY 42/42 + MINE-TRACES DEFECTS — see BLACKROSE_CHECKPOINT.txt newest block for detail):
  - Owner verification of the 42-doc knowledge corpus, content review FIRST
    (knowledge_verify proves a file is UNCHANGED since ingest — integrity,
    not truth): a subagent read all 42 docs and found 1 major factual error
    (bacteria "most successful by biomass" — plants hold ~80% of Earth's
    biomass), 6 minor (TΔΔS Gibbs typo, half-a-tennis-court alveoli,
    "CO2 not O2" as absolute, WWII death toll attached to both world wars,
    2008 crisis cited as authoritarian-information failure, 6 in of water
    "takes a car off the road") and 8 text corruptions — all 15 fixed,
    10 files re-ingested (283 chunks, 42/42 retrievable).
  - scripts/verify-corpus.ts (new) drives the EXPORTED
    knowledgeVerifyTool.run for every corpus item (--check read-only,
    --limit N): 42 verified, 0 stale, 0 unreadable, 0 unverified.
  - Two FAIL-OPEN miner defects found live while proving the soak pipeline
    and fixed: (1) resolveRuns preferred ANY top-level .jsonl, so
    ~/.blackrose/experience_memory.jsonl shadowed traces/ and the real
    trace was never read — "1 run, no-run_end" over the wrong file; (2)
    readTrace(dataDir,id) always derives <dataDir>/traces/<id>.jsonl, so
    the documented --data <traces dir> form read ZERO rows and graded every
    run no-run_end. Directory now resolved once (resolveTarget), reads go
    through new exported readTraceFile(file, runId).
  - src/mine-traces.test.ts (new): 4 spawn-based tests pinning both
    defects; npm test 539/539.
  - Gates: typecheck 0; scan:secrets clean (16 staged) + scan:history clean
    (469 commits); verify:checkpoint PASS (sha256 c2f9ee4974f2).
  - SPEND CAP: budget.json has NO cap key, so spend is UNCAPPED — and the
    owner was asked before the soak and explicitly declined a limit ("i
    dont want any limits though"), so uncapped is a recorded DECISION, not
    an oversight. Standing: exposed API keys from an unfiltered env dump
    need rotation; openai2 fetch failures + oxion 401 (the latter now has a
    router-side tool ceiling, see the block above).

BUILD QUEUE ITEM SHIPPED (2026-11-10, P1 TRACE WIRING — see BLACKROSE_CHECKPOINT.txt newest block for detail):
  - Every host that dispatches a run now opens a labeled trace, so a soak
    produces mineable data: runGoal owns ONE trace for the whole goal
    (source 'goal', or a host-supplied label) covering the planner call
    (timed by hand, model row), every step run and the verify run, closed
    by a LAST goal-level run_end with cumulative turns (readTrace's
    last-wins end reports the goal, not the verify segment); failedGoal is
    the chokepoint that closes failing runs. Host labels: bridge /ask ->
    'bridge', bridge /goal -> 'bridge-goal' (passed in, no double-start),
    bridge sub-agents -> 'bridge-sub-agent', schedule firing -> 'schedule'.
    Web /goal self-starts 'goal' (sibling of /api/ask's askTraceId) and
    telegram goals route through tgGoal only — no double traces.
  - 5 new tests (src/trace-wiring.test.ts, appended to npm test); 535/535.
  - Gates: typecheck 0; scan:secrets clean (6 files) + scan:history clean
    (468 commits); verify:checkpoint PASS (sha256 17ba5b11de91).

BUILD QUEUE ITEM SHIPPED (2026-11-09, G1 — see BLACKROSE_CHECKPOINT.txt newest block for detail):
  - G1: the --ui web host now runs the schedule runner (src/ui/web/main.ts
    runWebUi). The defect: index.ts returned from runWebUi at line 148-151
    BEFORE the console host's startScheduler() call at line 442, so
    scheduled tasks silently never fired while the desktop app ran behind
    the web UI. runWebUi now starts the same fail-closed runner (fresh
    buildSystem per mission, Telegram schedule pushback, per-dataDir
    scheduler role lock so a second host can't double-fire) and stop()
    releases it before h.close().
  - 3 source-pinning tests (src/ui/web/main.test.ts, wired into npm test);
    npm test 530/530.
  - Gates: typecheck 0; scan:secrets clean (4 staged) + scan:history clean
    (467 commits); verify:checkpoint PASS (sha256 6bc3a3ed2d18).

BUILD QUEUE ITEM SHIPPED (2026-11-09, T4 — see BLACKROSE_CHECKPOINT.txt newest block for detail):
  - T4 pairing-code owner binding (src/tools/telegram.ts): an OPT-IN
    one-time code that disables TOFU (first-message binding) while armed.
    Minted host-side only — telegram tool action:pair, approval-gated —
    8-char base64url (48 bits) in the sealed vault; while armed only
    /pair <code> binds, a successful pair consumes the code, compare is
    timing-safe (SHA-256 both sides); action:unpair restores TOFU; no code
    armed = legacy TOFU byte-for-byte. Status surfaces (ownerPreview,
    online note) show the armed state; forget clears the pair field.
  - 4 new tests (routing, e2e bind/consume against a local fake Bot API,
    TOFU-unchanged, tool lifecycle + gates); npm test 527/527.
  - Gates: typecheck 0; scan:secrets + scan:history clean (466 commits);
    verify:checkpoint PASS (both copies byte-identical, sha256 f9a3c9e8b5d6).

BUILD QUEUE ITEMS SHIPPED (2026-11-09, see BLACKROSE_CHECKPOINT.txt newest block for detail):
  - Pinned eval task suite (src/eval/): 8 end-to-end benchmark tasks (tool
    orchestration, graph two-hop, planted-failure recovery, a must-refuse
    destructive action, two-session persistence) run through the real agent
    and graded via the same trace -> eval_report pipeline as live runs;
    thresholds seeded so the gate is armed, red direction proven by tests;
    wired into npm test; CLI node src/eval/run.ts [--keep].
  - GraphRAG fusion (src/memory/graphrag.ts, wired into graph_search): BFS
    candidates re-ranked by cosine over cached entity vectors; full-graph
    fallback when no entity name matches; 5 tests.
  - Trace miner (scripts/mine-traces.ts, npm run mine:traces): denials,
    recovered/stuck/repeated errors, slow successes, loops, p95 model
    latency — validated live against the eval-suite traces.
  - Gates: typecheck 0; npm test 523/523; scan:secrets + scan:history clean;
    verify:checkpoint PASS (both copies byte-identical, sha256 b9c6b024bc8d).

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
  T4 (pairing-code owner binding) SHIPPED 2026-11-09 — see the newest
  checkpoint block; was "held for the owner" since this audit.

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
