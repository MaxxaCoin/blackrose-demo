# Runtime & Release Verification (task_0003)

Verifier: runtime-&-release role. Date: 2026-10-02.
Inner repo: `C:\Users\pc\Desktop\BlackRose\cline\blackrose` @ branch `main` (28 commits ahead of origin), working tree clean.
Method: read-only inspection + file:line citations + read-only inspection of `~/.blackrose` state and the installed app. No builds, no installer runs, no secrets printed.

---

## (a) B5 EMBEDDING ROOT CAUSE + USER-VISIBLE IMPACT + FIX

### Backend selection (`src/memory/embedder.ts`)
- Two backends: `gemini` (primary, `gemini-embedding-001`, 3072-dim, one batched HTTP call) and `hash` (`br-hash-v1`, 256-dim, pure-JS feature hashing from `embed.ts`). `embedder.ts:34`.
- Selection is by configuration on **every** call: `embedBatch()` uses Gemini when `BLACKROSE_EMBED !== 'off'` AND a key is present (`embedKey()` at `embedder.ts:116-118` reads `BLACKROSE_EMBED_API_KEY` -> `BLACKROSE_GEMINI_API_KEY` -> `GOOGLE_AI_API_KEY`). Otherwise it returns the hash embedder. `embedder.ts:236-261`.
- Batching: `MAX_BATCH = 8` (`embedder.ts:61`), `BATCH_PAUSE_MS = 2000` between batches (`embedder.ts:69`). NOTE: the comment at `embedder.ts:97` still says "MAX_BATCH=25" — stale doc drift vs the code constant `8`.
- Retry ladder: `MAX_RETRIES=4`, 2s->15s backoff (`embedder.ts:83-85`); 429/5xx retried, 4xx not.

### Daily-quota detection (the 429 quota-id branch)
- `DAILY_QUOTA_ID = 'EmbedContentRequestsPerDayPerProjectPerModel-FreeTier'` (`embedder.ts:157`); `DAILY_QUOTA_FREE_TIER_REQUESTS = 1000` (`embedder.ts:109`).
- On a 429, `isDailyQuotaExhausted(res)` reads the response body and checks for that quota id (`embedder.ts:160-167`). If present, it logs the exact warning seen live in the smoke run and returns `null` **without retrying the ladder** (`embedder.ts:188-198`):
  `[embed] Gemini daily embedding quota is exhausted (... 1000/day). Falling back to the hash embedder — retrieval stays lexical until the quota resets. No retry: the cap is per day.`
- A plain per-minute 429 or 5xx instead backs off and retries (`embedder.ts:200-206`). A null from any batch makes `embedBatch` discard the whole set and fall back to hash for the entire call (`embedder.ts:245-260`) — never a mix of vector spaces.
### Why the vector store refuses to save fallback vectors (`src/memory/vectors.ts`)
- Every stored entry records `{v, h}` where `h = textHash(text)` (fnv1a fingerprint). Header records `{model, dim}`. `vectors.ts:20-22`.
- `loadStore()` sets `hadRealIndex = true` **only if a usable, non-empty index was adopted from disk at load time** (`vectors.ts:58-76`).
- In `vectorsFor()`, if the embed result's model/dim differs from the store header (a fallback happened mid-flight), the store is reset in memory and `unsafeFallback = true` is set (`vectors.ts:105-117`).
- `saveStore()` REFUSES to write when `unsafeFallback && hadRealIndex` (`vectors.ts:185-192`), logging:
  `[vectors] not saving: br-hash-v1 fallback vectors would overwrite the real index. Retrieval is degraded to lexical for this session only.`
  Reason (documented `vectors.ts:109-116, 164-192`): the hash embedder "works", so searches silently succeed while overwriting a real 3072-d index with 256-d lexical vectors. Observed live 2026-09-30 (the `index.json.hash-poison-222606.bak` file is that incident's artifact). When `hadRealIndex === false` the fallback write is allowed (self-healing; header names the fallback so a healthy run rebuilds).

### USER-VISIBLE CONSEQUENCE
When the daily quota is spent, semantic search silently degrades to **lexical-only** retrieval for that session. Answers still return (no error surfaced), but "how do I deploy" no longer retrieves "release checklist steps" — only keyword-overlap matches.
- BlackRose automatically switches to simpler (keyword) search when the quota runs out — so it never fails, but it is less smart for the rest of the day.
- The only signal is one `console.warn` line on the core's stderr. Because `saveStore` refuses, the last-good index is preserved, so the loss is bounded to the session (re-embeds after quota reset).

### Real vector index vs corpus (read-only, `C:\Users\pc\.blackrose\vectors\`)
| file | model | dim | entries |
|---|---|---|---|
| `index.json` (current, 2026-10-01) | `gemini-embedding-001` | 3072 | **371** |
| `index.json.hash-poison-222606.bak` (incident artifact) | `br-hash-v1` | 256 | 644 |
| `index.json.pre-warm.bak` (pre warm-up) | `gemini-embedding-001` | 3072 | 11 |

The real (Gemini) index holds 371 chunks; the poison backup shows the corpus is ~644 chunks. So ~273 chunks are currently un-embedded and embed lazily on first touch (`vectors.ts:104-150`).

### Is 1000/day enough?
- Per the header comment the corpus is ~643 chunks (`embedder.ts:97`). At the actual `MAX_BATCH=8`, a full warm-up is ~81 requests — comfortably inside 1000/day **for a single clean run**.
- It is NOT enough when the day's budget is shared: the smoke suite, ad-hoc searches and earlier same-day experiments all draw from the same 1000. That is exactly how the observed run tripped the cap ("the cap was already partly spent by earlier experiments that same day", `embedder.ts:99-101`). So 1000/day suffices for one deliberate warm-up but is fragile under normal interactive use + tests on the same key.

### Concrete recommended fix
1. **Re-index after quota reset** (immediate, zero code): let the window roll over and run the warm-up once; un-embedded chunks self-heal lazily anyway (`vectors.ts:104-150`). Lowest risk.
2. **Reduce request count** to raise headroom: raise `MAX_BATCH` toward the measured-safe ceiling (the code's own comment says n=25 returned 200, `embedder.ts:48-54`) while keeping `BATCH_PAUSE_MS` pacing — turns ~81 requests into ~26.
3. **Second embedding provider / local fallback**: a local model (checkpoint references `nomic-embed-text` as a prior backend, `vectors.ts:15`) would remove the daily cap entirely. **No such mitigation exists** — embeddings are single-provider by design (`embedder.ts:24-26`).
4. **Surface the degradation in the UI**: today it is a no-op console.warn; `/api/health` could report the active backend so the tray/doctor shows "retrieval: lexical".

**Does code already mitigate it?** Partially: the refuse-to-save guard (`vectors.ts:185-192`) prevents permanent index destruction, and lazy re-embedding (`vectors.ts:104-150`) self-heals missing chunks. Nothing reduces the request count or adds a second provider. Status: **root-caused; the degradation is by design (degrade, never fail) and not permanently destructive.**

---

## (b) RELEASE / VERSION TRUTH TABLE

Every version string in the tree is **0.9.8** — the three manifests agree:

| source | field | value | citation |
|---|---|---|---|
| `desktop/tauri/tauri.conf.json` | `version` | `0.9.8` | tauri.conf.json:4 |
| `desktop/tauri/Cargo.toml` | `[package] version` | `0.9.8` | Cargo.toml:3 |
| `package.json` | `version` | `0.9.8` | package.json:3 |

### Updater endpoint — is it still a placeholder?
- Endpoint: `https://github.com/MaxxaCoin/BlackRose/releases/latest/download/latest.json` (`tauri.conf.json:45`). **This is NOT a placeholder** — it points at the real public artifacts host `github.com/MaxxaCoin/BlackRose`. (The checkpoint's older "placeholder" note at `BLACKROSE_CHECKPOINT.txt:705-706` predates the repo going live; `BLACKROSE_CHECKPOINT.txt:717-719` records it live since v0.8.1.)
- `pubkey` is present (a base64 minisign public key, `tauri.conf.json:47`) — the matching private key is `~/.tauri/blackrose.key` (outside the repo), used by `sign-098.out`.
- `release-098.out` confirms the release actually published: `https://github.com/MaxxaCoin/BlackRose/releases/tag/v0.9.8`.

### Installed app vs repo (read-only)
- Installed binary `%LOCALAPPDATA%\BlackRose\BlackRose.exe` VersionInfo: `ProductVersion 0.9.8`, `FileVersion 0.9.8`, `ProductName BlackRose`.
- NSIS uninstall/install registry key `HKCU\Software\BlackRose\BlackRose` -> `(Default) = C:\Users\pc\AppData\Local\BlackRose`, `Installer Language = 1033`. (The checkpoint gotcha stands: this key remembers the last install dir; delete it for a clean-location install.)
- **Installed app == repo version (both 0.9.8).** No version skew: the update NOTICE path would correctly report "up to date" against the v0.9.8 release.

---

## (c) UPDATE-INSTALL PATH — STILL UNVERIFIED (confirmed)

### The code that implements it
- **`update_install` command** — `desktop/tauri/src/main.rs:223-290`. Flow: `updater.check()` -> `update.download(...)` (main.rs:245-255) -> **kill the spawned core** so the installer can overwrite `node/node.exe` (main.rs:257-267) -> `update.install(bytes)` (main.rs:269-271) -> a fallback `handle.restart()` after 8s if the NSIS hooks did not relaunch us (main.rs:281-288).
- **NSIS hooks** — `desktop/tauri/installer-hooks.nsh`: `NSIS_HOOK_PREINSTALL` runs `taskkill /F /IM BlackRose.exe` (line 14) to free the locked exe; `NSIS_HOOK_POSTINSTALL` runs `ExecShell "open" "$INSTDIR\BlackRose.exe"` (line 20) to bring the new version back up.
- **Command ACL** — `desktop/tauri/build.rs:11-16` declares `update_install`, `update_notice`, `update_check`, `app_shutdown` so the loopback UI may invoke them.

### Confirmed unverified — from the checkpoint + the log gap
- `BLACKROSE_CHECKPOINT.txt:662-667`: "verify the update INSTALL path (the only unverified feature). The update NOTICE path is already proven ... What has never run end-to-end is **download -> NSIS closes the app -> relaunch -> process cleanup**, which is exactly what the `update_install` command and the NSIS hooks in build.rs exist for."
- The validation evidence corroborates the gap: **no log records an update-install run.** The only installer log is `validation/desktop-installer-smoke.out` (2026-09-19, **v0.8.0**), which proves a FRESH silent install + normal close-kills-core (RunEvent::Exit) — it does **not** exercise the download -> taskkill -> postInstall-relaunch sequence. The 098 evidence set (`build-098`/`sign-098`/`release-098`) covers build/sign/publish only. The `install-09x.exe` artifacts are just files, with no update-install log beside them.

### Precisely what remains unverified
1. That clicking "Install vX & restart" on an OLD installed version completes `download()` against the real endpoint.
2. That the NSIS `preInstall` `taskkill` actually frees the locked `BlackRose.exe` (and that the core was already stopped by main.rs:257-267), so `install()` does not fail with "Error opening file for writing".
3. That the `postInstall` `ExecShell` relaunch actually starts the NEW version, and that the 8s fallback `handle.restart()` (main.rs:281-288) fires only if the process survived the hooks.
4. Process cleanup after the update: exactly ONE window and ONE core remain (the single-instance guard collapses the postInstall-relaunch vs. self-restart race that caused two shells+two cores on the 0.9.0 update, per main.rs:89-94 and the main.rs:271-280 comment), and no orphan `node.exe` core survives.

### Minimal verification recipe (one real update, ~10 lines):
1. Bump to 0.9.9 and publish to the live endpoint (`tauri.conf.json` bump + `build:desktop` + sign + `gh release upload` with BOM-less `latest.json` (recipe at `BLACKROSE_CHECKPOINT.txt:655-661`).
2. On this machine, keep the installed **0.9.8**, launch it, click "Install v0.9.9 & restart".
3. Observe: (a) the download completes, (b) the app closes with no "Error opening file for writing", (c) a BlackRose window relaunches reporting the new version, (d) Task Manager shows exactly one `BlackRose.exe` and one `node.exe` core, and (e) `%LOCALAPPDATA%\BlackRose\crash-reports\` stays empty.

---

## (d) ORPHAN-CORE REAPER + SINGLE-INSTANCE GUARD

### Single-instance guard
- Registered **first**, before any other plugin: `tauri_plugin_single_instance::init(...)` — `desktop/tauri `main.rs:86-101`, dep `tauri-plugin-single-instance = "2.4.5"` (Cargo.toml:19), which raised MSRV to rustc 1.90 (Cargo.toml:6-9).
- **Guarantee:** at most one `BlackRose.exe`. A second launch (double-click, shortcut, installer relaunch) focuses/unminimizes the existing window instead of starting a second copy (`main.rs:95-101`).
- **Why it exists:** the 0.9.0 update left TWO shells + TWO cores because the updater's `postInstall` relaunch raced the app's own restart (`main.rs:89-94`). Two cores = two schedulers firing the same unattended tasks.
- **Failure mode:** it only stops a second `BlackRose.exe`. It **cannot** kill a `node core/blackrose.mjs` that outlived its shell (killed shell, failed update, crash) — that is the reaper's job (`main.rs:371-376`).

### Orphan-core reaper
- `reap_orphan_cores()` — `main.rs:37-80`. Enumerates `node.exe` via PowerShell `Get-CimInstance Win32_Process`, matches `CommandLine -like '*<exe_dir>\core\blackrose.mjs*'`, excludes our own freshly-spawned child pid, and `Stop-Process -Force`s the rest. Windows-only (`#[cfg(target_os = "windows")]`).
- **Off the boot critical path:** `boot_core` sets `SharedChild` (main.rs:370) and only then spawns a background thread for the reaper (main.rs:383-389). Commit `709bd63` "perf: take the orphan reaper off the boot critical path" (git log). PowerShell enumeration costs ~1.2s (measured 2026-09-28, main.rs:379-382).
- **Guarantee:** when PowerShell is available, any `node .../core/blackrose.mjs` left by a previous shell (killed shell, failed update, crash) is killed at boot, so the new window is not attached to a stale core. Observed live 2026-09-28: a 0.9.1 core kept serving on its old port while a 0.9.2 shell started, so the window attached to the OLD core and the mic button 404'd (main.rs:371-376).

### Failure modes (reaper)
1. **Path-dependent match (main gap):** the reaper matches `CommandLine -like '*<exe_dir>\core\blackrose.mjs*'` (main.rs:40-44, 59-60). Only a core launched by the PACKAGED shell (core next to the exe) matches. A dev-run core (`node dist/blackrose.mjs --ui ...` or `node src/index.ts --ui`) does NOT match and will NOT be reaped — such an orphan survives. Not the production case, but it means the reaper is not a general "kill all BlackRose cores" tool.
2. **Silent best-effort:** the PowerShell call is fire-and-forget (stdout/stderr nulled, main.rs:67-69); if PowerShell is unavailable or blocked, the reaper is a no-op with no user-visible signal (only a stderr line on success, main.rs:71-73).
3. **Narrow pid-race:** `our_pid` is read from `SharedChild` with `unwrap_or(0)` (main.rs:384-388). If that read fails (lock poisoned / state missing) at thread start, `keep_pid=None` and the reaper could kill our own freshly-spawned core. Low probability because `SharedChild` is set at main.rs:370 before the thread spawns.
- **Net guarantee:** single-instance stops a second shell; the reaper (best-effort, Windows-only, path-matched) stops a stale PACKAGED core. Neither guarantees zero orphans for dev-run cores or when PowerShell is unavailable.

---

## (e) ROUTE-HEALTH MECHANISM

### How it is computed
- `src/llm/routeHealth.ts` holds an **in-memory `Map`** registry keyed by `name::model` (`routeHealth.ts:16, 20-22`). No persistence, no TTL.
- `classifyRouteFailure()` maps a failure message to a tray state (`routeHealth.ts:25-37`): `429|quota|rate-limit|overloaded|billing|credit` -> **degraded** (red, recovers on its own); `401/403/404|unauthorized|forbidden|auth|not found|no such model` -> **down** (yellow, needs attention); `fetch failed|timeout|ECONN|ENOTFOUND|refused|network` -> **down**; anything else -> **degraded**.
- `src/llm/router.ts` writes the registry as a side effect of real traffic: `recordRouteSuccess(route.name, route.model)` on a winning call (`router.ts:33`) and `recordRouteFailure(route.name, msg, route.model)` on a losing one (`router.ts:38`). Multi-key routes classify each key separately via `keyHealth.ts` (`router.ts:102-118`).

### How it is surfaced
- `GET /api/health` returns `routes: getRouteStates()` alongside provider/model/counts (`src/ui/web/server.ts:361-378`). At startup `startWebUi` pre-registers the router's routes as `'unknown'` so the tray shows every route before the first call (`server.ts:216-225`; `registerRoute` -> `routeHealth.ts:55-66`).
- The page polls `/api/health` and paints a box per route (green=ok, red=degraded, yellow=down, gray=unknown).

### Is `routes[]` fed by real probes? — **No.**
- **`recordRouteProbe` exists but is NEVER called** (`routeHealth.ts:86-97`; repo-wide grep finds the definition only, zero call sites). The registry is updated ONLY by real router calls (success/failure) and by the startup `registerRoute` ('unknown').
- Consequence: a route shows `'unknown'` until its first real call; after a single failure it stays red/yellow until the next call succeeds. There is no periodic background probe refreshing the tray, and no TTL/cache expiry — the checkpoint's design note ("refreshed by doctor-style probing, cached ~30-60s", `BLACKROSE_CHECKPOINT.txt:811-813`) describes a plan that the shipped code did NOT implement.
- `src/doctor.ts` DOES perform live probes (`probeOpenAi`, `doctor.ts:26-69`; per-route probing `doctor.ts:83-145`) — but only via the `node src/index.ts --doctor` CLI. It is **not** wired into `/api/health`. So the tray reflects observed traffic, not active reachability.

---

## (f) AUTHORITATIVE EVIDENCE-LOG INDEX

### Authoritative for 0.9.8 (dated 2026-09-28, the 0.9.8 build/publish session)
| log | what it proves | authoritative? |
|---|---|---|
| `validation/build-098.out` | `blackrose@0.9.8` build: TS emit + bundle (62 modules) + `BlackRose_0.9.8_x64-setup.exe` produced, `blackrose-desktop v0.9.8` compiled in 4m46s | **YES** (build) |
| `validation/sign-098.out` | updater signing succeeded, `BlackRose_0.9.8_x64-setup.exe.sig` (420 bytes), `signer exit: 0` | **YES** (sign) |
| `validation/release-098.out` | release published: `https://github.com/MaxxaCoin/BlackRose/releases/tag/v0.9.8` | **YES** (release) |
| `validation/sign-098.err` | empty (0 bytes) — no signing errors | YES (corroborating) |

### No `test-098.out` exists
The 0.9.8 evidence set covers build/sign/release only. The most recent full-suite log is `validation/smoke-retry.out` (2026-09-30, ends `SMOKE TEST PASSED`). The session baseline (`node src/smoke.ts` => 200 PASS/0 FAIL; `node --test src/regression.test.ts` => 51 pass) is newer than any log on disk and is the authoritative test evidence.

### Stale / superseded logs (do NOT use as current evidence)
| log(s) | why stale |
|---|---|
| `reg-final.out` (2026-09-30) | reports `tests 18 / pass 18` — does **not** match the current regression suite (44 `test()` definitions; session baseline 51 pass). Partial/old run. |
| `embed-probe.out` (2026-09-16) | describes the **old local-Ollama** embedder ("configured qwen2.5-coder:7b could not embed", `model=br-hash-v1`). Current `embedder.ts` is API-only Gemini (`gemini-embedding-001`). Contradicts current code. |
| `build-097*`, `sign-097`, `release-097`, `install-092..097.exe` | previous versions (0.9.2-0.9.7); superseded by 098. |
| `desktop-boot.out`, `desktop-boot2.out` (09-18) | "NO binary is built" — pre-dates the first successful desktop build. |
| `warm-embed*.out`, `warm6.out` | embedding warm-up experiments (09-30) — informative for B5, not release evidence. |
| `npmtest*.out`, `test-ui*.out`, `test-dnd*.out`, `tc-*.out` | older UI/suite runs (09-16..09-28); superseded. |
| `apify-*`, `ig-live*`, `ytdlp-*`, `kira-probe.out`, `toolprobe-1.out` | unrelated feature probes; contain expected failures, not release regressions. |

### Contradictions with current code (flagged)
1. `embed-probe.out` (old local embedder) vs current API-only `embedder.ts` — stale, not a live contradiction.
2. `reg-final.out` test count (18) vs current suite (44 defs / 51 pass) — stale.
3. `build-098.out` notes `SEA skipped: no objcopy/llvm-objcopy` — so `npm run build:exe` does **not** produce a standalone `BlackRose.exe` on this machine; the shipped artifact is the Tauri/NSIS installer, and the CLI is launched via `dist/BlackRose.cmd`. This is a current limitation, not a regression.

---

## SUMMARY (most urgent first)
1. **B5 (URGENT, user-visible):** the Gemini free tier's 1000/day embedding cap silently degrades semantic search to lexical-only for the rest of the day. Not destructive (the refuse-to-save guard at `vectors.ts:185-192` protects the real index; ~273 of ~644 chunks currently un-embedded self-heal lazily), but invisible to the user. Fix priority: re-index after quota reset; then reduce request count (raise `MAX_BATCH` toward the measured-safe 25) and/or add a local/second embedder; surface the active backend in `/api/health`.
2. **Update INSTALL path UNVERIFIED** (confirmed by `BLACKROSE_CHECKPOINT.txt:662-667` + no log): download -> NSIS taskkill -> postInstall relaunch -> single-instance/cleanup has never run end-to-end. Recipe in section (c).
3. **Version truth is clean:** all manifests 0.9.8; updater endpoint points at the real `github.com/MaxxaCoin/BlackRose`; installed app is also 0.9.8 (no skew).
4. **Reaper/single-instance:** single-instance guarantees one shell; the orphan reaper (best-effort, Windows-only, path-matched) cleans stale PACKAGED cores but not dev-run cores or when PowerShell is unavailable.
5. **Route health:** `/api/health` `routes[]` reflects real traffic only — `recordRouteProbe` is defined but never called, so there is no active probing/TTL; the tray shows 'unknown' until the first call.
