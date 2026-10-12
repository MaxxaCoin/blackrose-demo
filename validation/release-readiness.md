# BlackRose Release Readiness — v0.9.9 (task_0003)

Verifier: release-readiness role. Date: 2026-10-02.
Repo: `C:\Users\pc\Desktop\BlackRose\cline\blackrose`, branch `main`, **34 commits ahead of `origin/main`**.
Scope rule honoured: **nothing was built, signed, installed, bumped or published.** No `makensis`, no `gh release create`, no `gh release upload`, no version edit. All proof below is dry-run / read-only / throwaway-path evidence.

---

## 0. PRE-PUBLISH BLOCKERS (read this first)

### BLOCKER 1 — the working tree is NOT clean
The task brief says "working tree is clean". **It is not.** `route-health` is mid-flight with uncommitted edits:

```
$ git status --porcelain
 M src/llm/factory.ts
 M src/llm/routeHealth.ts
 M src/smoke.ts
 M src/ui/web/main.ts
 M src/ui/web/server.ts
?? after-reg-err.txt
?? after-reg.txt
?? after-smoke-err.txt
?? after-smoke.txt
?? baseline-reg-err.txt
?? baseline-reg.txt
?? baseline-smoke-err.txt
?? baseline-smoke.txt

 src/llm/factory.ts     | 69 ++++++++++++++++++++++++++++++++++++++++++++++++++
 src/llm/routeHealth.ts | 50 +++++++++++++++++++++++++++++++++---
 src/smoke.ts           | 67 ++++++++++++++++++++++++++++++++++++++++
 src/ui/web/main.ts     | 49 +++++++++++++++++------------------
 src/ui/web/server.ts   | 16 ++++++------
 5 files changed, 216 insertions(+), 35 deletions(-)
```

The PASS counts in section 1 are **the gate results of the in-flight tree**, not of `origin/main`. Do not publish until `route-health` commits and the tree is clean.

### BLOCKER 2 — stale-bundle guard will refuse to stage (benign, but know it)
```
dist/blackrose.mjs          2026-10-01 21:59:59
newest file in src/        2026-10-02 11:31:12   <-- src/ is NEWER
```
`scripts/build-desktop.ts:166-172` throws `dist/blackrose.mjs is STALE`. Fail-closed working as designed: `npm run build:desktop` = `npm run build:exe && node scripts/build-desktop.ts`, so `build:exe` regenerates the bundle first. It only bites if someone runs `node scripts/build-desktop.ts` alone.

### BLOCKER 3 — `src-tauri/` does not exist
The brief cites `src-tauri/tauri.conf.json` and `src-tauri/Cargo.toml`. **Both are ENOENT.** The Tauri shell lives at `desktop/tauri/`. There is **no `.github/` directory and no CI workflow at all** — the release is a fully manual, single-machine operator procedure.

### Not blockers (checked, green)
| item | state |
|---|---|
| `cargo`/`rustc` | 1.98.1 present (Cargo.toml MSRV 1.90 — satisfied) |
| `node` | v24.21.0 (engines `>=24`) |
| updater private key `~/.tauri/blackrose.key` | **present** |
| `gh` | 2.101.0, authed as `MaxxaCoin`, scopes `gist, read:org, repo` |
| `objcopy`/`llvm-objcopy` | **absent** — SEA `.exe` skipped (known, `build-098.out`); irrelevant to the Tauri release |
| `pwsh` 7 | **not installed** — see section 3.5, this is why the BOM recipe matters here |

---

## 1. GATES — re-run verbatim, 2026-10-02

Both long suites were run detached (they exceed the 30 s tool timeout); logs in `validation/rr/`.

### 1.1 `npx tsc --noEmit`
```
EXIT=0
```
No diagnostics. **PASS.**

### 1.2 `node src/smoke.ts` -> `validation/rr/smoke.out` (14 403 B), `smoke.err` (9 087 B), exit **0**
Counted from the log: **207 PASS / 0 FAIL** (brief said 203 — the delta is `route-health`'s new checks). Verbatim tail:
```
  PASS - undo: BLACKROSE_UNDO=0 turns the journal off completely
  PASS - undo stays out of the web UI read-only allowlist (it overwrites files)
  PASS - undo always asks even in trust mode (the rollback path is destructive)

  workspace: C:\Users\pc\AppData\Local\Temp\blackrose-smoke-TkQTd2
SMOKE TEST PASSED
```
`smoke.err` contains only the non-fatal, **expected** Gemini free-tier notice (repeated):
```
[embed] Gemini daily embedding quota is exhausted (EmbedContentRequestsPerDayPerProjectPerModel-FreeTier, 1000/day). Falling back to the hash embedder - retrieval stays lexical until the quota resets. No retry: the cap is per day.
```

### 1.3 `node --test src/regression.test.ts` -> `validation/rr/reg.out`, `reg.err` (0 B), exit **0**
```
tests 51
suites 0
pass 51
fail 0
cancelled 0
skipped 0
todo 0
duration_ms 55287.1522
```
**51/51 PASS**, ~55 s. `reg.err` empty (0 bytes).

### 1.4 Reconciliation with the brief
| gate | brief | observed | verdict |
|---|---|---|---|
## 2. VERSION CONSISTENCY AUDIT

### 2.1 Every surface, measured

| # | surface | file:line | value |
|---|---|---|---|
| 1 | `package.json` | `cline/blackrose/package.json:3` | `0.9.8` |
| 2 | Tauri config `version` | `cline/blackrose/desktop/tauri/tauri.conf.json:4` | `0.9.8` |
| 3 | Cargo `[package] version` | `cline/blackrose/desktop/tauri/Cargo.toml:3` | `0.9.8` |
| 4 | Version constant in `src/` | — | **none exists.** grep `0\.9\.` over `src/**/*.ts` returns only two **comments** (`src/smoke.ts:2461`, `:2480`, both historical). Nothing in `src/` hardcodes a version; the core never reads `package.json`. The Rust side gets its version from Cargo.toml via `CARGO_PKG_VERSION`. |
| 5 | Installed exe `ProductVersion` | `%LOCALAPPDATA%\BlackRose\BlackRose.exe` | `0.9.8` |
| 6 | Installed exe `FileVersion` | same file | `0.9.8` |
| 7 | Uninstall registry `DisplayVersion` | `HKCU\...\Uninstall\*`, `DisplayName: BlackRose` | `0.9.8` |
| 8 | GitHub latest release | `gh release list --repo MaxxaCoin/BlackRose` | `v0.9.8` — `Latest`, published `2026-09-28T15:55:44Z` |
| 9 | v0.9.8 assets | `gh release view v0.9.8` | `BlackRose_0.9.8_x64-setup.exe` (25 640 590 B, sha256 `66265ea3...`), `.sig` (420 B), `latest.json` (1 070 B) |

`InstallLocation = "C:\Users\pc\AppData\Local\BlackRose"`; `UninstallString = "C:\Users\pc\AppData\Local\BlackRose\uninstall.exe"`.

**Verdict: version truth is CONSISTENT at 0.9.8 across all live surfaces. No file is genuinely inconsistent — nothing reported as needing a fix, and nothing was edited.**

### 2.2 EXACT files to edit for 0.9.8 -> 0.9.9 (three edits, nothing else)

| file | line | current | target |
|---|---|---|---|
| `cline/blackrose/package.json` | **3** | `"version": "0.9.8",` | `"version": "0.9.9",` |
| `cline/blackrose/desktop/tauri/tauri.conf.json` | **4** | `"version": "0.9.8",` | `"version": "0.9.9",` |
| `cline/blackrose/desktop/tauri/Cargo.toml` | **3** | `version = "0.9.8"` | `version = "0.9.9"` |

**Do NOT touch** (mention 0.9.8 but are historical prose, not inputs): `cline/blackrose/docs/04-ROADMAP.md:130`, `:398`, `:399`; `validation/verify-runtime-release.md`. Optionally update the roadmap at release time for the record — cosmetic.

Registry (7) is **not hand-edited** — NSIS writes it on install. GitHub (8) is created by the recipe.

---

## 3. EXACT PUBLISH RECIPE (numbered — do not run under this role)

Preconditions: clean tree on `main`, `cargo`/`rustc` >=1.90, `node` >=24, `gh` authed, `~/.tauri/blackrose.key` present, **`BLACKROSE_SIGNING_PASSWORD` exported in the environment**.

### 3.1 Version bump
1. Edit the three files at section 2.2. Commit: `Release 0.9.9`.

### 3.2 Build the bundle
2. From `cline/blackrose`:
   `powershell -ExecutionPolicy Bypass -File scripts\build-desktop-signed.ps1 -OutLog ..\..\validation\build-099.out`
   which runs `npm run build:desktop` = `npm run build:exe` (tsc emit -> 62-module bundle -> `dist/blackrose.mjs`) **then** `node scripts/build-desktop.ts` (stages `core/blackrose.mjs` + `node/node.exe` + generated `icons/icon.ico`, validates the toolchain fail-closed, then `npx tauri build` -> NSIS).

   **REALISTIC DURATION — the big one.** Run it **detached and poll the log**; do not assume it hung:
   - Rust compile of `blackrose-desktop`: **~4 m 46 s** (measured, `validation/build-098.out`)
   - **makensis alone: ~35 minutes** (recorded gotcha, `BLACKROSE_CHECKPOINT.txt:54-56`)
   - **Total realistic budget: 40-50 minutes**, with both signing env vars set. Poll with `Get-Content validation\build-099.out -Wait`.

3. Expected artifacts in `desktop\tauri\target\release\bundle\nsis\`:
   - `BlackRose_0.9.9_x64-setup.exe` (~25.6 MB — 0.8.0 through 0.9.8 all landed 25 293 912 to 25 659 625 B)
   - `BlackRose_0.9.9_x64-setup.exe.sig` (~420 B; every 0.8.0-0.9.8 sig was exactly 420 B)
   - **Do not expect `dist\BlackRose.exe`** — `objcopy` is absent, so `build-exe.ts:280-289` prints `SEA skipped: no objcopy/llvm-objcopy tool found`. The installer is the deliverable; the CLI launches via `dist\BlackRose.cmd`.

### 3.3 Signing — environment only
4. `scripts/build-desktop-signed.ps1` is the signing entrypoint and is **fail-closed**:
   - reads the key **from outside the repo**: `$keyPath = "$env:USERPROFILE\.tauri\blackrose.key"` (lines 6-8); missing -> `Write-Error` + `exit 1`
   - `$env:TAURI_SIGNING_PRIVATE_KEY = [IO.File]::ReadAllText($keyPath)` (line 9) — **content, not a path**; `tauri build` rejects a path here (gotcha, `CHECKPOINT:56-58`)
   - `$env:TAURI_SIGNING_PRIVATE_KEY_PASSWORD = $env:BLACKROSE_SIGNING_PASSWORD` (line 14)
   - lines 10-13: **if `$env:BLACKROSE_SIGNING_PASSWORD` is empty the script errors and exits 1.** No fallback, no file read for the password — **environment only**.

   **`BLACKROSE_SIGNING_PASSWORD` must never be written into a repo file.** The script's own header (lines 3-5) says so. Export it into the current shell before step 2, e.g.
   `$env:BLACKROSE_SIGNING_PASSWORD = (Read-Host -AsSecureString | ConvertFrom-SecureString -AsPlainText)`
   and never commit it. Note `build-desktop.ts:212-215` *auto*-reads the private key when `TAURI_SIGNING_PRIVATE_KEY` is unset, so a bare `npm run build:desktop` signs but **cannot decrypt** the password-protected key.

   Verify signing happened: `.sig` exists at 420 B and `build-099.out` ends with the signer exiting 0. Past evidence: `validation/sign-098.out`, `sign-098.err` (0 bytes).

### 3.4 latest.json — the exact shape the Tauri updater expects
5. `node scripts/make-latest-json.mjs 0.9.9 "release notes"`

   Requires `desktop\tauri\target\release\bundle\nsis\BlackRose_0.9.9_x64-setup.exe` **and** its `.sig` (else exits 1); writes `latest.json` beside them. Shape (`make-latest-json.mjs:40-52`):

```json
{
  "version": "0.9.9",
  "notes": "<release notes>",
  "pub_date": "2026-10-02T12:34:56.789Z",
  "platforms": {
    "windows-x86_64": {
      "signature": "<base64 minisign signature, contents of the .sig, trimmed>",
      "url": "https://github.com/MaxxaCoin/BlackRose/releases/download/v0.9.9/BlackRose_0.9.9_x64-setup.exe"
    }
  }
}
```

   The endpoint in `tauri.conf.json:45` is `https://github.com/MaxxaCoin/BlackRose/releases/latest/download/latest.json`, so **`latest.json` must be an asset of the newest release** — upload it every time, or the updater keeps serving the previous manifest.

### 3.5 PROOF: latest.json carries no UTF-8 BOM
**Reproduced live on a throwaway path** (`validation/rr/bomtest/`, never the real bundle dir):

```
PS5.1  Get-Content | Out-File -Encoding utf8     first3=239,187,191  BOM=True   <-- BREAKS THE UPDATER
PS5.1  $json | Out-File -Encoding utf8            first3=239,187,191  BOM=True   <-- BREAKS THE UPDATER
       [IO.File]::WriteAllText(...)               first3=123,34,118   BOM=False  <-- SAFE
```

And the **live published v0.9.8 manifest**, byte-inspected:

```
bytes0-2: 123,13,10   (239,187,191 = BOM)     -> no BOM
len=1070
```

Why it matters: Tauri's Rust parser rejects a BOM'd manifest with `expected value` — a **previously-hit, recorded gotcha** in the script's own header (`make-latest-json.mjs:9-13`): *"don't 'simplify' this back into PowerShell."*

**Safe alternative on each shell:**
- **PowerShell 5.1 (this machine — `pwsh` is NOT installed):** `[System.IO.File]::WriteAllText($path, $json)` — proven BOM-free above. `-Encoding ascii` is also BOM-free but **wrong here** (the signature/notes are base64/UTF-8; ASCII mangles non-ASCII notes). Do **not** use `Out-File -Encoding utf8`.
- **pwsh 7:** `Set-Content -Encoding utf8NoBOM`, or `[IO.File]::WriteAllText`. Note `utf8NoBOM` **does not exist** in 5.1 — that is the trap.
- **The repository's canonical path is `node scripts/make-latest-json.mjs`**, which uses `fs.writeFileSync(..., 'utf8')` (line 52), re-reads the first 3 bytes itself, prints `BOM: none (good)` and **exits 1 if a BOM is present** (lines 54-59). Use it.

6. **Mandatory pre-upload BOM gate** (throwaway-safe):

```powershell
$b=[IO.File]::ReadAllBytes("<bundle>\latest.json"); $b[0..2] -join ','   # must NOT be 239,187,191
```

### 3.6 Upload
7. Create the release, then upload **with `--clobber`** so a retry overwrites instead of failing on duplicate assets:

```powershell
gh release create v0.9.9 --repo MaxxaCoin/BlackRose --title "BlackRose 0.9.9" --notes "..." --latest
gh release upload v0.9.9 `
  "desktop\tauri\target\release\bundle\nsis\BlackRose_0.9.9_x64-setup.exe" `
  "desktop\tauri\target\release\bundle\nsis\BlackRose_0.9.9_x64-setup.exe.sig" `
  "desktop\tauri\target\release\bundle\nsis\latest.json" `
  --repo MaxxaCoin/BlackRose --clobber
```

Single-line form as recorded in the checkpoint (`CHECKPOINT:661`):
`gh release upload v0.9.0 <exe> <sig> latest.json --clobber`

8. Post-upload verification: `gh release view v0.9.9 --json assets` shows all three assets; re-fetch `releases/latest/download/latest.json`, confirm `bytes0-2` is not `239,187,191` and `version == 0.9.9`. **Only then** will an installed 0.9.8 be offered the update.

**Total operator time: ~45-55 min, almost all of it makensis, plus a manual hardware step (section 5).**

## 4. RECONCILIATION WITH `validation/verify-runtime-release.md`

That document exists (179 lines, runtime-&-release role, 2026-10-02). Agreed and independently re-verified: version truth clean; update-INSTALL unverified and the code implementing it (`main.rs:223-290`, `installer-hooks.nsh:12-21`, `build.rs:11-16`); the latest.json BOM gotcha.

**Disagreements — flagged, not silently resolved:**

1. **Smoke count.** `verify-runtime-release.md:154` says the authoritative baseline is *"200 PASS/0 FAIL"*; the task brief says 203; I measured **207**. All three describe different trees. The only defensible number is the one measured on the tree you publish.
2. **`src-tauri/` paths.** `verify-runtime-release.md:64-66` correctly cites `desktop/tauri/...`; the **task brief** cites `src-tauri/...`, which does not exist. I used the correct paths.
3. **Commits ahead.** `verify-runtime-release.md:4` says **28**; git says **34** (matching the brief). The older doc is stale.
4. **On-disk `latest.json` is stale.** It is dated 2026-09-28 21:25, while the `0.9.8` `.sig` is 2026-09-28 21:23 and the `.exe` **2026-09-30 18:01** — the on-disk manifest predates the last-built 0.9.8 exe by ~2 days. Harmless (the published release matches its signature), but do **not** treat the on-disk `latest.json` as evidence about the current bundle; regenerate it.
5. **No CI.** Neither doc states it, and it is the most important structural fact: `.github/` does not exist, so the recipe in section 3 is 100% manual and single-machine-bound. A missed step fails silently.

---

## 5. UNVERIFIED-FEATURE REGISTER (needs a human with hardware)

These two **cannot** be proven from code, by inspection, or by the automated gates.

### (a) Update INSTALL path — end-to-end (this is the release's own acceptance test)
**Status: UNVERIFIED, and the ONLY unverified feature per `BLACKROSE_CHECKPOINT.txt:662-667`.** The update **NOTICE** path has been proven (0.8.1 displayed "update available: v0.9.0"); what has never run is the actual install.

Code under test: `main.rs:245-255` download (~25 MB) -> `main.rs:261-267` kill the spawned core so the installer can overwrite `node\node.exe` -> `main.rs:269-271` `update.install(bytes)` -> `installer-hooks.nsh:14` `NSIS_HOOK_PREINSTALL` `taskkill /F /IM BlackRose.exe` -> `installer-hooks.nsh:20` `NSIS_HOOK_POSTINSTALL` `ExecShell "open" "$INSTDIR\BlackRose.exe"` -> `main.rs:284-288` the 8-second `handle.restart()` fallback that must **not** fire (it raced the relaunch and produced two shells + two cores on the 0.9.0 update, `main.rs:89-94`).

**Prerequisites:** keep the **installed 0.9.8**; publish a real **0.9.9** per section 3. Confirm the banner appears on 0.9.8 *first* — if not, click nothing; the installed exe may already be newer than you think (gotcha, `CHECKPOINT:115-119`).

**Manual test script**

| # | step | expected observation |
|---|---|---|
| 1 | read `(Get-Item "$env:LOCALAPPDATA\BlackRose\BlackRose.exe").VersionInfo.ProductVersion` | `0.9.8` (the "old" side) |
| 2 | Task Manager; filter `BlackRose` + `node`. | exactly **1** `BlackRose.exe` + **1** core `node.exe` |
| 3 | Launch BlackRose from the Start menu; let it fully load. | window opens; no crash dialog |
| 4 | Sidebar -> **Check for update**. | banner naming **v0.9.9** (proves endpoint + manifest + pubkey agree) |
| 5 | **Start a screen recording** (this is the evidence). | recorder running |
| 6 | Click **Install v0.9.9 & restart**. | UI shows download progress |
| 7 | Watch the window during the install. | closes cleanly. **Any dialog reading "Error opening file for writing ... node\node.exe" or "...BlackRose.exe" = FAIL** — the locked-file bug these hooks prevent |
| 8 | Time the click-to-relaunch gap. | **~30 s to 2 min** (~25 MB + NSIS). A silent >30 s gap is normal, not a hang |
| 9 | New BlackRose window. | opens and is usable. **PASS only if** so |
| 10 | re-run the `ProductVersion` read from step 1 | `0.9.9` |
| 11 | Task Manager (same filter). | **exactly 1** `BlackRose.exe` + **1** core `node.exe`. **2+ of either = FAIL** (the 0.9.0 double-launch regression) |
| 12 | Sidebar -> **Check for update**. | "BlackRose is up to date" — no longer offers 0.9.9 |
| 13 | Wait 60 s, re-check Task Manager. | still 1 + 1 — the 8 s fallback did **not** double-launch |
| 14 | `Get-ChildItem "$env:LOCALAPPDATA\BlackRose\crash-reports"` | **empty**. Any file = the new build crashed on boot = FAIL |
| 15 | Send one real message; confirm the reply and that `~/.blackrose` history survived. | works; prior sessions still listed |

**Evidence to record:**
1. screen recording of steps 6-9
2. the two `ProductVersion` outputs (0.9.8 before / 0.9.9 after)
3. Task Manager capture at steps 2 and 11 showing 1+1
4. `Get-ChildItem ...\crash-reports` output (empty)
5. app stderr, which should contain `core stopped for the update install` (`main.rs:265`) and `download complete, handing over to the installer` (`main.rs:252`)
6. save all of the above to `validation/update-install-099.out` and append the outcome to `BLACKROSE_CHECKPOINT.txt`, replacing the `NEXT STEP 2` item at lines 662-667

**If step 7 fails:** do not retry blindly. Capture the exact NSIS error text and the `%TEMP%` installer log; the likely cause is `installer-hooks.nsh:14` `taskkill` racing `main.rs:263` `child.kill()`.

### (b) Second-device `.aistate` / bridge sync — needs TWO machines on a private LAN
**Status: UNVERIFIED.** `docs/04-ROADMAP.md:396` records it as an open box: *"bridge + `--sync-push`/`--sync-pull` are implemented and smoke-verified but never exercised between two real machines; needs a 2nd device to complete."* Smoke proves serialization locally; it cannot prove transport, auth, conflict handling, or a second OS.

**SECURITY: private/trusted LAN ONLY. Do NOT port-forward or expose the bridge to the public internet** (`CHECKPOINT:687-690`: its LAN-only HTTP design is *not* a security boundary).

**Setup — identical on BOTH machines**

| var | value |
|---|---|
| `BLACKROSE_STATE_PASSWORD` | **the same strong value on both** (this is what encrypts the payload) |
| `BLACKROSE_BRIDGE_TOKEN` | one stable shared token, both machines |
| `BLACKROSE_BRIDGE_HOST` | `0.0.0.0` on the primary only |
| `BLACKROSE_BRIDGE_URL` | `http://<primary-lan-ip>:<port>` on the secondary |

Get the primary's LAN IP with `ipconfig` (e.g. `192.168.1.42`) and open the firewall for the bridge port on the primary only.

**Manual test script**

*Phase 0 — preconditions*
1. Confirm both machines are on the **same private LAN**; record both IPs.
2. Back up `~/.blackrose` on **both** devices first: `Compress-Archive -Path "$HOME\.blackrose" -DestinationPath "$HOME\Desktop\blackrose-backup-<date>.zip"`. **This is destructive testing — the sync path overwrites state.**
3. Record `blackrose --doctor` output on both.

*Phase 1 — reachability*
4. Start the bridge on the primary with `BLACKROSE_BRIDGE_HOST=0.0.0.0`.
5. From the secondary: `curl http://<primary-lan-ip>:<port>/health` (or the repo's `--health` flag).
   -> expect HTTP 200 + healthy JSON. **Non-200 = stop, diagnose routing/firewall/token before going further.**
6. Repeat with a **deliberately wrong** `BLACKROSE_BRIDGE_TOKEN`.
   -> expect **401/403**. **A 200 here is a security FAIL — stop and fix the token check before any sync.**

*Phase 2 — pull*
7. On the **primary**, create something unmistakable: add a memory "PRIMARY-CANARY-AAA" and save a file "primary-file.txt".
8. On the **secondary**, run `--sync-pull`.
   -> expect a success report naming the restored files, and "PRIMARY-CANARY-AAA" present. **Verify content, not just a success line.**
9. Restart the secondary app; confirm the pulled memory survives (proves it landed on disk, not just in memory).

*Phase 3 — independent edits + conflict*
10. **Without syncing**, edit the SAME memory on the secondary ("SECONDARY-CANARY-BBB").
11. On the primary, edit that same memory differently ("PRIMARY-CANARY-CCC"). Record both texts.
12. On the secondary run `--sync-pull`, then `--sync-push`.
    -> expect the conflict to be **detected and surfaced**, with **both** versions preserved in a conflict copy. A silent overwrite of either edit is a **FAIL** — that is data loss.
13. Confirm you can read the conflict copy and reconcile manually.

*Phase 4 — push + convergence*
14. `--sync-push` from the secondary; then `--sync-pull` back on the primary -> expect convergence and a clean report.
15. Repeat push/pull once more on both -> **idempotent**: zero conflicts, zero churn on the second pass.

*Phase 5 — negative*
16. Stop the primary's bridge; run `--sync-push` on the secondary.
    -> expect a **clean, explicit failure** ("bridge unreachable"), **never** a silent local write that looks like success.
17. Wrong `BLACKROSE_STATE_PASSWORD` on the secondary, attempt a pull.
    -> expect a clear decrypt/auth error, no partial write, no corruption.

*Phase 6 — cross-platform (if device B differs)*
18. If device B is not Windows, repeat Phases 2/4 and record the OS pair. The export/import path already rejects path-traversal, absolute-path and symlink/junction cases (proven by the regression suite) — but that suite is **local**, so cross-OS is new ground.

**Evidence to record:**
1. both LAN IPs and OS builds
2. verbatim `/health` from step 5 **and** the 401/403 from step 6
3. full stdout of steps 8, 12, 14, 15, 16, 17
4. listing of the conflict directory after step 12 with both canary strings visible
5. a video/screenshot of the secondary showing the pulled memory after a restart
6. save to `validation/two-device-sync.out`, replace the open box at `docs/04-ROADMAP.md:396` and `BLACKROSE_CHECKPOINT.txt:676-685`

---

## 6. SUMMARY

- **Gates:** tsc clean; smoke **207 PASS / 0 FAIL**; regression **51/51**, exit 0. All green on the *current dirty tree*.
- **Version truth: consistent at 0.9.8** across package.json, tauri.conf.json, Cargo.toml, installed exe (File+Product), uninstall registry DisplayVersion, and GitHub `v0.9.8` (3 assets). **No version constant exists in `src/`.**
- **To go 0.9.9, edit exactly three lines:** `package.json:3`, `desktop/tauri/tauri.conf.json:4`, `desktop/tauri/Cargo.toml:3`. Nothing else.
- **Blockers:** (1) tree is dirty — commit `route-health` first; (2) `dist/blackrose.mjs` is older than `src/`, so `build-desktop.ts` alone refuses to stage (`build:desktop` rebuilds it first — benign); (3) the brief's `src-tauri/` paths and `.github/workflows/` do not exist.
- **Recipe verified:** ~40-50 min, dominated by **~35 min of makensis**; signing is env-only (`BLACKROSE_SIGNING_PASSWORD`, fail-closed at `build-desktop-signed.ps1:10-13`, key read from outside the repo); `latest.json` shape documented; **BOM reproduced and safe alternative proven** (`Out-File -Encoding utf8` = BOM on 5.1; `[IO.File]::WriteAllText` / `utf8NoBOM` / the Node script = clean; live v0.9.8 manifest verified BOM-free).
- **Two unverified features require hardware:** the update-INSTALL path (section 5a, 15 numbered steps) and the two-device `.aistate`/bridge sync (section 5b, 18 steps in 6 phases). Publishing 0.9.9 is what makes 5a immediately executable — the release and its own acceptance test are the same action.
