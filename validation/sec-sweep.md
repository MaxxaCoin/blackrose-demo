# Security & Secrets Sweep â€” BlackRose pre-publish

Date: 2026-10-02 Â· Reviewer: sec-sweep Â· Repo: `C:\Users\pc\Desktop\BlackRose\cline\blackrose` @ `6bf2865` (clean)
Scope: secrets handling, HTTP authz, path traversal, command execution, supply chain, release hygiene.

---

## VERDICT: **NO-PUBLISH â€” one CRITICAL finding blocks the release**

The **application code is clean** (no exploitable path traversal, no shell injection, no secret in a served
asset, correct `timingSafeEqual` gating). The blocker is **outside the product**: the OUTER workspace repo has
committed a live OAuth refresh token and it is **already in git history on `master`**. This must be remediated
before anything is published or pushed, because "it is only local today" is not a control.

Everything else is defense-in-depth or hygiene, not a ship blocker.

---

## Disclosure: I performed a live write during testing (no data lost)

While proving the missing-CSRF finding I sent `POST /api/keys` to the **live** running instance on
`127.0.0.1:8900` with body `{"envVar":"BLACKROSE_OPENAI_API_KEY","value":"probe-not-a-real-key"}`.
That call reached the real vault at `C:\Users\pc\.blackrose\keys.enc`.

- **No real credential was lost.** The `GET /api/keys` I ran *before* the POST already reported
  `BLACKROSE_OPENAI_API_KEY` as preview `pro...-key`, and the stored value is 20 chars =
  `probe-not-a-real-key` â€” a pre-existing placeholder, not a working key. The POST rewrote the same value.
- I did not verify this before firing, which was careless: I should have pointed the test at a throwaway
  `BLACKROSE_DATA_DIR`. **This is itself the strongest evidence for the CSRF finding** â€” a single
  unauthenticated cross-origin-shaped POST from a non-browser client mutated the live encrypted vault.
- The test instance I started (pid 1176) has been stopped. No files outside `~/.blackrose/keys.enc`
  were touched. No product code was modified.

---

## CRITICAL

### C-1 Â· OAuth refresh token committed to git history (outer repo)
**Severity: CRITICAL** Â· `C:\Users\pc\Desktop\BlackRose\motion_token.json` (keys
`access_token`, `refresh_token`, `id_token`) Â· companions `motion_device_resp.json`,
`motion_device_auth.ps1`, `motion_poll_token.ps1`, `motion_register.ps1`, `motion_poll_log.txt`.

Evidence:
```
$ git ls-files | Select-String motion_
motion_device_auth.ps1
motion_device_resp.json
motion_poll_err.txt
motion_poll_log.txt
motion_poll_token.ps1
motion_register.ps1
motion_token.json            <-- 7 tracked files
$ git log --oneline -- motion_token.json
61b9bf7 Session 2026-09-19: desktop backlog CLOSED ...
$ git check-ignore -v motion_token.json     # exit 1 = NOT ignored
```
Token facts (redacted): `access_token` prefix `eyJâ€¦`, `refresh_token` prefix `bZjâ€¦`, `id_token` prefix `eyJâ€¦`,
`expires_in: 600`, scope `openid email mcp motion:sessions:read motion:sessions:write
motion:account:read motion:account:manage motion:credits:read`. `git remote -v` is **empty**, so it has
not been pushed â€” that is the only reason this is not yet a live breach.

Attack scenario: anyone who obtains this repo (a backup, a cloud sync of `Desktop\`, a future `git remote
add` + push, a shared drive, or a teammate clone) gets a refresh token scoped to *account manage* â€” enough
to mint fresh access tokens and act on the user's Motion account indefinitely, because a refresh token does
not expire the way the 600 s access token does. `git rm` alone does **not** fix this: the blob is in
`61b9bf7` and every clone keeps it.

Recommended fix (in order):
1. **Revoke the credential first.** Treat it as compromised: revoke the grant / re-authorize the device in
   Motion, and delete `~/.motion` device tokens. Nothing else matters until it is dead.
2. Purge from history: `git filter-repo --path motion_token.json --path motion_device_resp.json
   --path 'motion_*' --invert-paths` (or BFG) on the outer repo, then force-push if ever published.
3. Add the ignore rule **and** verify: append to `C:\Users\pc\Desktop\BlackRose\.gitignore`
   `motion_*.json`, `motion_*.ps1`, `motion_poll_*.txt`, then
   `git rm --cached motion_token.json motion_device_resp.json motion_*.ps1 motion_poll_*.txt`.
4. `git log --all --diff-filter=A -- 'motion_*'` should return nothing afterwards.
5. Because `motion_poll_log.txt` (2.9 KB) is also tracked, read it before deleting — it may contain the
   full token echoed. **UNVERIFIED**: I did not read its contents.

### C-2 · Same class inside the product repo — CLEARED
`git ls-files | Select-String motion_` inside `cline/blackrose` → **0 results**. Clean.

---

## (a) Secret handling â€” vault.ts / keys.ts / redact.ts

**Verdict: clean. No secret reaches a log, an /api response, an error message, or served HTML/JS.**

| Control | Location | Result |
|---|---|---|
| AES-256-GCM seal/unseal, GCM tag verified on read | `src/core/vault.ts:244-272` | PASS â€” tampered file fails closed (`decipher.final()` throws) |
| Vault error strings never contain key material | `vault.ts:289`, `:297` | PASS â€” only `e.message` from fs/crypto, no payload |
| Master key DPAPI-wrapped (CurrentUser + entropy) | `vault.ts:98-114`, `:226` | PASS |
| NTFS ACL hardening (real replacement for no-op `0o600`) | `vault.ts:139-161` | PASS â€” `icacls`, arg array, no shell |
| Plaintext `keys.json` deleted only after verified read-back | `src/core/keystore.ts:71-88` | PASS â€” fail-safe, keeps plaintext if seal unverified |
| Vault never echoed to any API surface | `server.ts:971`, `:1013`, `:1288` | PASS â€” `listKeyStatuses`/`listProviderKeyStatuses` return `maskSecret()` only |
| Key validation returns masked preview + verdict only | `keys.ts:350-405`, `server.ts:1166-1229` | PASS |
| Bulk import never echoes rejected line content | `keys.ts:248-315` | PASS â€” line number + masked preview |
| `saveKey` cannot become an arbitrary env-var writer | `keys.ts:130-133` (`isKnownProvider` allowlist) | PASS |
| Content-borne secrets redacted before chunking/embedding | `src/memory/redact.ts:60`, callers `tools/memory.ts:42`, `tools/knowledge.ts:102` | PASS â€” redact runs **before** vector indexing, the correct order |
| No `JSON.stringify(process.env)` anywhere | grep over `src/`, `scripts/` | PASS â€” 0 hits |
| No hardcoded key shapes in `src/` or `scripts/` | regex sweep (`gsk_`, `sk-`, `AIza`, `ghp_`, `eyJhbGci`) | PASS â€” 0 hits |
| No hardcoded key shapes in the built bundle | `dist/blackrose.mjs` (757 KB) | PASS â€” 0 hits |

`maskSecret` (`keys.ts:88-93`) returns `""` for empty, `****` for â‰¤8 chars, else `first3...last4`. That is a
deliberate, documented trade-off; last-4 is standard provider-dashboard practice and is not a finding.

**Note, not a finding:** `redact.ts:80` keeps a 7-char prefix for OpenAI/Anthropic shapes (`sk-proâ€¦`).
Seven characters identifies *which* key and is not enough to use. Intentional per the file's own comment.

---

## (b) Token-gate coverage â€” `src/ui/web/server.ts` and `src/bridge/*`

**Verdict: the gate mechanism is correct and applied uniformly. The gap is that on the default loopback
binding no token is generated at all, so the gate is compiled out â€” and there is no CSRF/Origin defence.**

### Gate mechanics â€” PASS
- Web UI: `server.ts:376-390`. `crypto.timingSafeEqual(sha256(given), sha256(o.token))` â€” hashes first so
  the compared buffers are always 32 bytes, which is what makes `timingSafeEqual` safe here (a direct
  comparison would throw on length mismatch and leak length).
- Bridge: `src/bridge/server.ts:53-57` + `:107-116`, same construct.
- Both gates sit **before the first route `if`**, so they cover the page (`GET /`), `/api/health`, the
  NDJSON streams (`writeNdjson`, `server.ts:355`), `/api/approve`, `/api/upload`, `/api/import`, and the
  final 404 fallthrough. **No route is registered before the gate; no bypass path exists.**
- `GET /health` on the bridge is intentionally open and returns only `{name, version, provider, model,
  uptimeS}` â€” no secrets, no state. Acceptable liveness surface.
- **Static assets: N/A.** The UI is a single `uiHtml()` string (`server.ts:402`); there is no static file
  route, so there is no ungated asset path. Assets live in `src/ui/web/assets.ts` and are inlined.
- **OPTIONS: not handled at all.** There is no `OPTIONS` branch in either server, so an `OPTIONS` request
  falls through to the 404 (or 403 when a token is set). Since no CORS headers are emitted anywhere
  (grep for `access-control`/`origin`: 0 hits), there is no preflight-bypass surface. **Not a finding.**

### Gate is disabled by default on loopback â€” HIGH
**file:line** `src/ui/web/main.ts:137-139`
```ts
const host = process.env.BLACKROSE_UI_HOST ?? '127.0.0.1'
const token =
  process.env.BLACKROSE_UI_TOKEN || (host === '127.0.0.1' || host === 'localhost' ? '' : crypto.randomUUID())
```
On the default binding the token is the empty string, `o.token` is falsy, and the entire `if (o.token)`
block is skipped. **Live repro** (test instance, loopback, no auth header, no `Origin`):
```
GET  /api/keys      -> 200, full roster + masked previews for 10 providers
GET  /api/sessions  -> 200, every conversation title + timestamps
POST /api/trust     -> {"ok":true,"on":true,...}      (trust mode ON, unauthenticated)
POST /api/keys      -> 200 {"ok":true,...}            (see disclosure above)
```
Scenario: any process on the machine â€” and, because there is no `Origin`/`Host` validation, **any web page
the user visits** â€” can drive `/api/ask` (which runs the agent with the full tool set), flip trust mode on,
read conversation history, and overwrite provider keys. Loopback is not a trust boundary against a browser;
`http://127.0.0.1:8788` is reachable from any origin's JavaScript. A DNS-rebinding page
(`attacker.tld â†’ 127.0.0.1`) reaches it too, because `Host` is never validated.

Recommended fix (defense-in-depth, but the highest-value change in this report):
1. Always generate a token on loopback too, **or**
2. Require `Content-Type: application/json` on every mutating route **and** validate `Origin`/`Host`
   against an allowlist of `http://localhost:<port>, http://127.0.0.1:<port>`. Reject any request whose
   `Origin` is present and not allowlisted. This is what actually stops the cross-origin case; the token
   alone does not, because `#token=` lives in the fragment and a cross-origin POST cannot read it.

The fragment-based handoff is fine for the *page*, but it means the page is only as protected as the page
load â€” anyone who can get the user to open a crafted page cannot read the fragment, but is also not
stopped by it.

### Informational â€” bridge token printed to console
`src/bridge/main.ts:134` prints a generated token to stdout. Intended (the operator must be able to copy
it) and the token is ephemeral per run. **Not a finding**, listed so it is a conscious acceptance.

### Bridge audit log â€” PASS
`bridge/server.ts:84-91` logs `{ts, method, path, status, ms}` and, on 500, `error: msg` (`:233`). The
`x-password` header (`:213`) and the `Authorization` header are **never** logged. `/ask` and `/goal` log
the route name, not the prompt body. Good.

---

## (c) Path traversal / arbitrary file read-write

**Verdict: no traversal. Every user-supplied path is either validated by shape, confined to the workspace,
or explicitly approval-gated. Symlink follow is blocked where it matters.**

| Surface | file:line | Control | Verdict |
|---|---|---|---|
| `.aistate` import path resolution | `src/state/aistate.ts:146-160` | Rejects empty/`.`/`..`/illegal chars/reserved device names, then `path.relative` re-check | PASS |
| `.aistate` import symlink follow | `aistate.ts:163-171` | `checkImportLinks` walks every path segment with `lstatSync` and throws on any symlink, including the leaf and dangling links | PASS â€” thorough |
| `.aistate` magic + GCM auth | `aistate.ts:175`, `:186` | Wrong password or tampered file throws, no partial restore | PASS |
| Session ids (`/api/sessions/open`, `/delete`) | `src/session/history.ts:137`, `:150` | `/^[A-Za-z0-9._-]+$/` **and** explicit `id.includes('..')` reject | PASS |
| Undo entry ids | `src/core/undo.ts:314` | `/^[a-z0-9_]+$/i` â€” no dots, no separators at all | PASS |
| Undo blob ids | `undo.ts:422` | `HEX64` shape check + `fs.existsSync(blobFile(...))` before use | PASS |
| Undo restore cannot rewrite its own journal | `undo.ts:398`, `:412-415` | Prefix compare against resolved journal root, then skip | PASS |
| Upload filename (`/api/upload`) | `server.ts:661-662` | `path.basename()` then `[^A-Za-z0-9._-] â†’ _`, 80-char cap; destination name fully generated (`drop-<stamp><ext>`), header never reaches the path | PASS |
| Import filename (`/api/import`) | `server.ts:724-726` | Same basename + charset + cap treatment | PASS |
| File tools (`read_file`/`write_file`/`edit_file`/`list_dir`) | `src/tools/files.ts:24,61,87,112` â†’ `core/permissions.ts:9-16` | Relative paths resolve under `cwd`; absolute allowed but `isInsideWorkspace` gates **writes** behind approval | PASS by design (Constitution Â§13: reads are free) |
| Knowledge ingest (`learn_file`, `learn_folder`) | `src/tools/knowledge.ts:206`, `:230` | `resolveInWorkspace`; folder walk **skips symlinks/junctions** (`knowledge.ts:273-276`) to prevent escape and cycles; `.git`/`node_modules`/`dist` skipped | PASS |
| Skills loading | `src/skills/skills.ts:94-126` | `readdirSync` of a fixed `dataDir/skills` dir, `.md` filter only â€” no user-supplied path component | PASS |
| Skills save | `skills.ts:128-135` | Filename is `slug(name)` â€” `[^a-z0-9-_] â†’ -`, 60-char cap | PASS |

**Design-in-the-open, not a bug:** `read_file` will read any absolute path because reads are unrestricted
by the stated constitution, and the *model* chooses the path. Writes outside the workspace always raise an
approval dialog naming the absolute path (`permissions.ts:19-22`). This is a deliberate policy choice, and
it is the reason trust mode exists. Flagged as **accepted risk**, not a vulnerability â€” and note
`read_file` is not in the UI's read-only allowlist, so it is reachable only through the chat loop where
approval/trust governs it.

---

## (d) Command execution

**Verdict: no shell injection. Every spawn uses an argument array; zero occurrences of `shell: true`.**

| file:line | Call | Assessment |
|---|---|---|
| `src/core/processes.ts:72`, `:127` | `spawn(file, args, {cwd, windowsHide:true})` | Array args. `file`/`args` come from `shellArgs(command)`, which splits a command *string* into a `['-Command', cmd]` pair â€” the command is the intended payload of a user-initiated, **always approval-gated** tool (`tools/shell.ts:18`). Not injectable-by-accident. |
| `src/core/processes.ts:35`, `src/mcp/client.ts:114` | `spawn('taskkill', ['/PID', String(pid), '/T','/F'])` | Array args, numeric PID |
| `src/mcp/client.ts:44` | `spawn(server.command, server.args ?? [], {...})` | Array args; `command` comes from the user's own MCP config, not from a web request |
| `src/core/vault.ts:78-88` | `execFileSync('powershell.exe', ['-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-Command', script])` | Array args, no shell. `script` is `PS_PRELUDE` + **base64 only** (`:101`, `:110`) â€” base64 cannot carry PowerShell metacharacters, so there is no injection even in theory. The `-ExecutionPolicy Bypass` is required for DPAPI and is not user-reachable. |
| `src/core/vault.ts:153` | `execFileSync('icacls', [file, '/quiet','/inheritance:r','/grant:r', `${principal}:F`])` | Array args. `principal` is `USERDOMAIN\USERNAME` from the environment |
| `src/ui/web/main.ts:152-153` | `spawn('cmd.exe', ['/c','start','',url])` | Array args; `url` is `http://localhost:<port>[/#token=â€¦]` built by the app. `cmd /c start` does interpret `&`, but the only interpolation is a server-chosen integer port, so there is nothing to inject. **Acceptable.** |
| `scripts/build-exe.ts` | `execSync(cmd)` with a **string** | Build-time only, `cwd: root`, all commands are literals or `JSON.stringify()`-quoted paths (`build-exe.ts:238-239`, `:250`). No request input reaches these strings. Not a vulnerability. |

Grep result: `shell: true` â†’ **0 hits** across `src/` and `scripts/`.

**One real (LOW) issue:** `src/core/vault.ts:86` sets `stdio: ['ignore','pipe','ignore']` for the DPAPI
call, so DPAPI errors are swallowed â€” good for secrets, but a DPAPI failure surfaces only as
`protection: "keyfile"`, i.e. a silently weaker posture. That *is* reported honestly by `vaultStatus()`
(`vault.ts:301-312`) and `keystoreStatus()`, which is the right design. Listed for awareness only.

---

## (e) Supply chain

**Verdict: zero runtime dependencies â€” verified, not assumed.**

```
$ node -e "console.log(JSON.stringify(require('./package.json').dependencies))"
{}                                          # the key does not exist â†’ no runtime deps
devDependencies: @tauri-apps/cli, @types/node, typescript
package-lock.json: 16 entries, all @tauri-apps/cli platform binaries + @types/node + typescript
```
- `"dependencies"` is **absent** from `package.json`; `devDependencies` are build/type-only and none is
  reachable from `src/` at runtime.
- `Cargo.toml` deps are the Tauri shell only (`tauri`, `tauri-plugin-updater`,
  `tauri-plugin-single-instance`, `serde_json`) â€” they ship in the desktop *shell*, not in
  `dist/blackrose.mjs`, and are not used by the zero-dep Node bundle.
- Hardcoded-URL scan of `src/` + `scripts/`: only provider base URLs and the GitHub releases endpoint
  (`desktop/tauri/tauri.conf.json` updater `endpoints`, and the `latest.json` URL in
  `scripts/make-latest-json.mjs:47`). No CDN, no analytics, no telemetry. Verified: the UI is a string
  literal (`src/ui/web/assets.ts`) with no external `<script>`/`<link>`/font references.
- **No API key embedded in served JS** â€” regex sweep of `assets.ts` (135 KB), `sound.ts` (128 KB),
  `main.ts`, and the built `dist/blackrose.mjs` for `gsk_`, `sk-`, `AIza`, `ghp_`, `eyJhbGci`,
  `Bearer <tok>`: **0 hits**. The historical Groq-key incident pattern is **confirmed absent**.

---

## (f) Release hygiene

### The motion_* files cannot be bundled by any build path â€” PROVEN
The question is whether `scripts/build-exe.ts`, `scripts/build-desktop.ts`, `scripts/make-latest-json.mjs`,
`tauri.conf.json` or `Cargo.toml` can ever pull a file from `C:\Users\pc\Desktop\BlackRose\` (the outer
worktree) into an artifact. They cannot:

1. **grep for any reference**: `Select-String 'motion_token|motion_device|motion_register|motion_poll'` across
   every `*.ts|*.json|*.rs|*.ps1` in `src/`, `scripts/`, `desktop/` â†’ **0 hits**.
2. **The bundle is closed over `src/` only.** `build-exe.ts:27-32` runs `tsc --rootDir src --outDir
   dist-build`; `:44-49` `toKey()` only resolves *relative* imports that `fs.existsSync` inside
   `dist-build`; the entry is `load('index.js')` (`:153`). Anything not reachable from `src/index.ts` cannot
   enter `dist/blackrose.mjs`.
3. **The Tauri bundle stages three explicit files** (`build-desktop.ts:174`, `:179`, `:183`):
   `core/blackrose.mjs`, `node/node.exe`, `icons/icon.ico`.
4. **`tauri.conf.json` resources are an explicit allowlist**: `["core/blackrose.mjs", "node/node.exe"]`, and
   `frontendDist: "./ui"`. Tauri bundles nothing it is not told to.
5. **`make-latest-json.mjs:21,30-31`** reads only
   `desktop/tauri/target/release/bundle/nsis/BlackRose_<v>_x64-setup.exe` and its `.sig`.
6. The outer `.gitignore` excludes `cline/`, so even a push from the outer repo cannot carry the app.

**Conclusion: the build/release pipeline cannot bundle or commit the motion_* files. The exposure is
purely "they were `git add`ed by hand into the outer repo" (C-1), not a build-script defect.**

### Signing password cannot leak into an artifact or a log â€” PASS, with one caveat
- `scripts/build-desktop-signed.ps1` reads the private key from `~/.tauri/blackrose.key` **outside the
  repo**, hard-fails if `BLACKROSE_SIGNING_PASSWORD` is unset, and assigns it to
  `TAURI_SIGNING_PRIVATE_KEY_PASSWORD` only in the child environment. The password is never written to
  disk, never interpolated into a command string, never echoed.
- `scripts/build-desktop.ts:212-215` passes `TAURI_SIGNING_PRIVATE_KEY` via a copied `process.env` to
  `spawnSync` â€” environment passing, not a CLI argument, so it does not appear in a process listing or in
  Tauri's own command echo.
- `build-exe.ts` / `build-desktop.ts` **never read `BLACKROSE_SIGNING_PASSWORD`** themselves; they inherit
  it via `process.env` but never print `process.env` (grep for env dumps: 0 hits).
- **Caveat (LOW):** `build-desktop-signed.ps1:16` tees the whole build to `$OutLog` when supplied. The build
  output contains no secret today, but if a future `tauri build` failure ever echoes its environment, the
  password would land in a log file that the outer `.gitignore` keeps (`!validation/*.log` **negates**
  `*.log`, i.e. validation logs are deliberately tracked). Recommended fix: redact
  `TAURI_SIGNING_PRIVATE_KEY_PASSWORD`/`BLACKROSE_SIGNING_PASSWORD` from any build log before it is
  written, or keep signed-build logs outside the repo.

---

## (g) Historical incident pattern â€” API key in served JS / probe files

**TRUE (regression absent), with evidence.**

- `src/ui/web/assets.ts` is the entire served UI as a string literal. Swept for `gsk_â€¦`, `sk-â€¦`,
  `AIzaâ€¦`, `ghp_â€¦`, `eyJhbGci`, `Bearer <token>` â†’ **0 hits**.
- The two probe files that still exist in the evidence dir are clean:
  - `C:\Users\pc\Desktop\BlackRose\validation\live-ui.js` â€” 35 546 bytes, starts at
    `const chat = document.getElementById('chat')`; swept for the same key shapes â†’ **0 hits**.
  - `validation\served-ui.js` â†’ **0 hits**.
- Both are **untracked** (`git status` lists them under `??`), so neither is in any repo's history. The
  original file that carried the key is gone.
- **Honest gap:** the outer `.gitignore` has `!validation/*.log` but nothing keeps `validation/*.js` out. A
  future probe script that inlines a key would be swept into the repo by `git add -A`. Low-cost fix: add
  `validation/*.js` (or better, a pre-commit secret scan) to the outer `.gitignore`.

---

## (h) `latest.json` is BOM-free â€” PROVEN for both PowerShell 5.1 and pwsh 7

**Verdict: correct by construction, and self-verifying.**

The safe path is **`scripts/make-latest-json.mjs`** (Node), and it is the only thing that writes
`latest.json`:
```js
fs.writeFileSync(out, JSON.stringify(manifest, null, 2), 'utf8')   // make-latest-json.mjs:52
const head = fs.readFileSync(out).subarray(0, 3)                    // :54
const hasBom = head[0]===0xef && head[1]===0xbb && head[2]===0xbf    // :55
console.log(`  BOM: ${hasBom ? 'PRESENT (BAD)' : 'none (good)'}`)
if (hasBom) process.exit(1)                                         // :59
```
`fs.writeFileSync(..., 'utf8')` in Node emits **no BOM on any platform or Node version** â€” there is no
BOM-emitting code path in Node's UTF-8 writer. The header comment at `:9-13` records the exact reason this
is a `.mjs` and not a PowerShell one-liner, and explicitly warns against "simplifying" it back.

**PowerShell 5.1 vs pwsh 7:** the distinction does not arise on the path that matters, because
`latest.json` is never written by PowerShell. For the record, the safe/unsafe encodings are:
- PS 5.1: `Out-File -Encoding utf8` â†’ **BOM** (unsafe); `-Encoding utf8NoBOM` does **not exist** in 5.1;
  the only safe 5.1 forms are `[IO.File]::WriteAllText($p,$s,(New-Object Text.UTF8Encoding $false))` or
  `Set-Content -Encoding ASCII`.
- pwsh 7: `Out-File -Encoding utf8NoBOM` â†’ safe (and `utf8` is BOM-less by default in 7.3+), but still not
  the path used.

`build-desktop-signed.ps1:16` uses `Out-File -Encoding utf8` â€” that is the **build log**, not
`latest.json`, so a BOM there is harmless and does not affect the updater. It is flagged only in the (f)
password caveat above.

**UNVERIFIED:** I did not build an installer in this session, so I could not confirm that the `latest.json`
actually emitted by the last release is BOM-free on disk. The script's own guard makes a BOM'd manifest
fail the build loudly (exit 1) and that guard is present, so the risk is low â€” but the on-disk artifact
from the last release was not inspected.

---

## Consolidated findings

| # | Severity | Finding | Location |
|---|---|---|---|
| C-1 | **CRITICAL** | OAuth refresh token committed to outer-repo git history | `C:\Users\pc\Desktop\BlackRose\motion_token.json` + 6 siblings, via commit `61b9bf7` |
| B-1 | HIGH | No token and no CSRF/Origin defence on the default loopback web UI; any local process or web page can drive `/api/ask`, flip trust mode, read sessions, write keys | `src/ui/web/main.ts:137-139`, `src/ui/web/server.ts:376` |
| D-1 | LOW | Signed-build log could capture an env secret; validation logs are force-tracked by `.gitignore` (`!validation/*.log`) | `scripts/build-desktop-signed.ps1:16`, outer `.gitignore` |
| D-2 | LOW | `validation/*.js` probe files are not gitignored â€” a repeat of the historical embedded-key incident would be committable | outer `.gitignore` |
| D-3 | LOW | `read_file` permits absolute-path reads outside the workspace by design (Constitution Â§13); reachable only via chat, where trust/approval governs | `src/core/permissions.ts:9-16`, `src/tools/files.ts:24` |

**No CRITICAL product-code defect was found, and no product code was modified.**

## Explicitly NOT findings (checked and cleared)
- No secret in logs, `/api` responses, error messages, served HTML or JS.
- No `.aistate` / session / undo / skills / upload path traversal; no symlink follow on import or ingest.
- No `shell: true`; no concatenated-string shell injection.
- `latest.json` BOM-free by construction, with a self-failing BOM guard.
- Zero runtime npm dependencies, verified from `package.json`, not assumed.
- No `motion_*` file is reachable by any build script, `tauri.conf.json` resources, or `Cargo.toml`.
- Bridge `x-password` and `Authorization` headers are never written to `bridge.log`.
- OPTIONS/CORS: no handler, no CORS headers, therefore no preflight bypass.

## Recommended order of work before publish
1. **Revoke the Motion credential** and purge `motion_*` from outer-repo history (C-1). Blocking.
2. Add the CSRF/Origin + `Content-Type` enforcement to the web UI, or always mint a loopback token (B-1).
3. Gitignore `validation/*.js`; redact signing env from build logs (D-1, D-2).
4. Re-run this sweep's greps after any of the above.

