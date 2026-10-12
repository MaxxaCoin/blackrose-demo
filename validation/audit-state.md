# BlackRose audit — state / session / schedule / bridge / desktop / build

Audited: `src/state/aistate.ts`, `src/session/history.ts`, `src/schedule/runner.ts`,
`src/bridge/{server,client,main}.ts`, `src/skills/skills.ts`, `src/core/executive.ts`,
`src/tools/goals.ts`, `scripts/build-exe.ts`, `scripts/build-desktop.ts`,
`desktop/tauri/src/main.rs`, `desktop/tauri/build.rs`.
Commit `b1f9cbe`. Every finding below was reproduced by executing the real code, not
inferred by reading. Categories that came back clean are stated explicitly.

## Resolution — all 8 rows closed in 0.9.15

| # | Fixed in | Commit |
|---|----------|--------|
| 1 | Scheduler rejection no longer terminates Node | (earlier release) |
| 2 | Goal-ID path traversal | (earlier release) |
| 3 | Atomic session write + guarded parse | `35a8bed` |
| 4 | UTC/local rollover, non-positive intervals | (earlier release) |
| 5 | Bounded boot-health read | (earlier release) |
| 6 | Signing key now opt-in (`BLACKROSE_RELEASE=1`) | `54034db` |
| 7 | `stop_core()` returns `Result`; install aborts loudly | `a4425de` |
| 8 | Export stamp: ms + random, no more collision | `54034db` |

Row 7 and row 6 were the two nobody had claimed. Row 6 was verified NOT to
weaken the real release path: `scripts/build-desktop-signed.ps1` sets
`TAURI_SIGNING_PRIVATE_KEY` explicitly, which the new gate passes through.

## Severity-ranked summary

| # | Sev | CONFIRMED | Location | Issue |
|---|-----|-----------|----------|-------|
| 1 | High | CONFIRMED | `schedule/runner.ts:38,50` | Unhandled rejection from the scheduler timer **kills the whole process** |
| 2 | High | CONFIRMED | `core/executive.ts:95` + `tools/goals.ts:142` | Goal `id` is unvalidated → `writeOne` path traversal writes **outside `dataDir`** |
| 3 | Medium | CONFIRMED | `session/history.ts:22-24,31` | Non-atomic session write + unguarded `JSON.parse` → one truncated file **permanently bricks** that session |
| 4 | Medium | CONFIRMED | `tools/schedule.ts:74-77` | `dailyAt` mixes UTC date with local hours → unattended task **fires twice** on the same local day |
| 5 | Medium | CONFIRMED | `desktop/tauri/src/main.rs:492-501` | `health_ok()` has no read timeout → boot can **hang forever**, 90 s cap unreachable |
| 6 | Medium | CONFIRMED | `scripts/build-desktop.ts:213-215` | Updater **private signing key** auto-loaded into the build child's env, no opt-in |
| 7 | Low | CONFIRMED | `main.rs:129-130, 263-264, 341-342` | `let _ = child.kill()` swallows failure right before the installer runs → half-installed app |
| 8 | Low | CONFIRMED | `bridge/server.ts:199-201`, `aistate.ts:124-126` | Second-resolution export stamp → concurrent exports collide on one path |

---
## 1. High — CONFIRMED — scheduler timer can crash the entire BlackRose process

`src/schedule/runner.ts:37-39` fires the tick on an interval and discards the promise:

```ts
const timer = setInterval(() => { void tick() }, tickMs)   // :37-39
```

`tick()` (`runner.ts:90-100`) has a `finally` but **no `catch`**, and `runOne`'s
`try/catch` only opens at `runner.ts:66` — i.e. *after* the `loadSchedules` /
`saveSchedules` pair at `runner.ts:45-51`. Any throw from that earlier block escapes
`tick()` as a rejected promise that nobody handles, and Node's default
`--unhandled-rejections=throw` terminates the process.

Reproduced: a read-only `schedules.json` (EPERM on write) kills the app in ~50 ms.

```
Error: EPERM: operation not permitted, open '...\.audit-sch\schedules.json'
    at saveSchedules (src/tools/schedule.ts:41:6)
    at runOne (src/schedule/runner.ts:50:7)
    at tick (src/schedule/runner.ts:96:34)
    at Timeout._onTimeout (src/schedule/runner.ts:38:10)
PROCESS EXIT CODE 1
```

Impact: any transient write failure — file locked by a virus scanner, another process
holding `schedules.json`, read-only profile, disk full — takes down the CLI, the web
UI and the desktop shell from a background timer. This is a denial of service on the
whole product, not just the scheduler.

The same shape exists at `runner.ts:85`: `appendLog` is called *inside the `catch`
block*. If the log append fails (the likely cause of the original failure), the catch
handler throws again and produces the identical unhandled rejection.

Fix: wrap the whole `tick` body in `try/catch`, or attach
`.catch((e) => o.onEvent?.(...))` at `runner.ts:38`, and move the `try` above
`runner.ts:45`.

## 2. High — CONFIRMED — path traversal in goal persistence (arbitrary write outside `dataDir`)

`src/core/executive.ts:92-96`:

```ts
fs.writeFileSync(path.join(dir, `${prefix}_${rec.id}.json`), ...)
```

`rec.id` is never validated. `saveGoal` (`executive.ts:121-123`) is called from
`goal_update` (`tools/goals.ts:142`) with `next.id` taken from the record found by
`getGoal`, i.e. straight out of the JSON on disk.

`goals/` is listed in `STATE_DIRS` (`aistate.ts:42`), so a goal record's **contents**
are attacker-controllable via any `.aistate` import — the import validator
(`aistate.ts:146-160`) checks *paths*, never the JSON body. The poisoned id then
round-trips through `goal_list` (`tools/goals.ts:150-156` prints `g.id`) and the model
echoes it into `goal_update`.

## 3. Medium — CONFIRMED — a truncated session file permanently breaks that session

`src/session/history.ts:31` writes the live session file in place — no temp file, no
rename. A crash, power loss or full disk mid-write leaves a truncated JSON document.

`saveSession` then re-reads that file at `history.ts:22-24` with an **unguarded**
`JSON.parse`, unlike every other read in the module (`:71`, `:118`, `:140` are all
wrapped in `try`). So the first save after the corruption throws, and it will throw on
*every* subsequent save for that id — the session is unrecoverable.

Reproduced against the real module:

```
loadSession on truncated: null
loadLatestSession: null
saveSession THREW: Expected ',' or '}' after property value in JSON at position 44
```

Impact: silent, permanent loss of a conversation. It is also self-concealing —
`loadSession` and `loadLatestSession` swallow the parse error and return `null`, so the
session just vanishes from the sidebar with no diagnostic anywhere.

Fix: write to `${p}.tmp` and `fs.renameSync` over the target, and wrap the
`history.ts:23` parse in a `try` that falls back to `created: now`.

## 4. Medium — CONFIRMED — `dailyAt` schedules double-fire outside UTC

`src/tools/schedule.ts:73-78`:

```ts
const today = now.toISOString().slice(0, 10)          // UTC date
if (s.lastRun && s.lastRun.slice(0, 10) === today) return false
const [h, m] = s.dailyAt.split(':').map(Number)
## 5. Medium — CONFIRMED — `health_ok()` can block forever, making the boot timeout dead code

`desktop/tauri/src/main.rs:490-502`:

```rust
let Ok(mut stream) = TcpStream::connect_timeout(&addr, Duration::from_millis(600)) else { ... };
...
let _ = stream.read_to_string(&mut body);   // :500 — NO read timeout
```

Only `connect` is bounded. `read_to_string` on a socket with no read timeout blocks
until the peer sends data or closes. The boot loop's 90 s guard
(`main.rs:451`, `BOOT_TIMEOUT_SECS`) is only evaluated *between* `health_ok()`
iterations, so if the port accepts the connection and never answers, the loop never
reaches line 451 and the splash screen sits there indefinitely. A hung core, a
half-started node, or any process that grabs the port produces a permanently stuck
window with no error and no timeout.

Compounding: `free_port()` (`main.rs:504-509`) binds port 0, reads the port, then
**drops the listener** before `spawn_core` runs — a textbook TOCTOU. Another process
can take the port in between, and `health_ok`'s only assertion is
`body.contains("blackrose-ui")` (`main.rs:501`), which any process can satisfy.

Fix: `stream.set_read_timeout(Some(Duration::from_millis(600)))` before the read, and
make `free_port()` hand the listener to the child (or hold it until spawn succeeds).

## 6. Medium — CONFIRMED — updater signing key silently injected into the build

`scripts/build-desktop.ts:212-215`:

```ts
const env: NodeJS.ProcessEnv = { ...process.env }
if (!String(env.TAURI_SIGNING_PRIVATE_KEY ?? '').trim() && fs.existsSync(updaterKeyPath)) {
  env.TAURI_SIGNING_PRIVATE_KEY = fs.readFileSync(updaterKeyPath, 'utf8')
}
```

A plain `npm run build:desktop` on any machine that has `~/.tauri/blackrose.key` reads
the **minisign private key** and puts it in the environment of a child process, with no
prompt and no opt-in flag. `validateToolchain` (`build-desktop.ts:110-112`) only reports
the key as "present" in a check-list line; it never signals that the key will be used.
## 7. Low — CONFIRMED — core-kill failure is swallowed immediately before the installer runs

`desktop/tauri/src/main.rs:261-267`:

```rust
if let Some(mut child) = state.lock().unwrap().take() {
    let _ = child.kill();      // :263  failure discarded
    let _ = child.wait();      // :264  failure discarded
    eprintln!("core stopped for the update install");
}
```

The comment at `main.rs:257-260` explains that the core *must* be stopped or the
installer fails with "Error opening file for writing: ...\node\node.exe" and leaves a
half-installed app. That is precisely the scenario these two `let _ =` statements hide:
if `kill()` fails the code still prints "core stopped" and proceeds into
`update.install(bytes)` (`main.rs:269-271`), converting a recoverable error into the
documented broken install. Same pattern at `main.rs:129-130` (exit hook) and
`main.rs:341-342` (`app_shutdown`), where a failed kill leaves an orphan core serving
on its old port — the exact condition `reap_orphan_cores` (`main.rs:37-80`) exists to
clean up on the *next* launch.

Fix: check the `kill()` result and return `Err` to the page instead of continuing.

## 8. Low — CONFIRMED — concurrent exports collide on a one-second-resolution filename

`src/state/aistate.ts:124-126` stamps the delta filename with
`new Date().toISOString().replace(/[:.]/g,'-').slice(0,19)` — second resolution
(verified: two calls 300 ms apart produce different stamps, but two calls in the same
second produce the identical name). The same pattern is at `aistate.ts:97-99`.

`bridge/server.ts:199-201` makes this reachable over the network:

```ts
const delta = exportStateIncremental(o.dataDir, body.password)
---

## Categories audited and found clean

**`.aistate` import path traversal / zip-slip — CLEAN.** `importTarget`
(`aistate.ts:146-160`) rejects single-component paths, absolute paths, `..`, NUL and
control characters, reserved Windows device names, and trailing dot/space; then
re-resolves and re-checks with `path.relative`. `checkImportLinks`
(`aistate.ts:162-171`) rejects symlinks at every path component including dangling ones
and the leaf. Entries are validated for the *entire archive* in the `.map()` at
`aistate.ts:203-206` before any write happens. No traversal found.

**AES-GCM auth tag verified before any write — CLEAN.** `decipher.setAuthTag(tag)` and
`decipher.final()` run at `aistate.ts:185-187`, inside a `try` that throws a generic
error. The first `fs.writeFileSync` in `importState` is at `aistate.ts:232`, strictly
after. A tampered archive cannot be partially written. This is correct as written.

**Bridge token comparison — CLEAN.** `server.ts:53-57` SHA-256s both sides and uses
`crypto.timingSafeEqual` on fixed-length digests, so there is no length or timing
oracle; `server.ts:78-80` enforces a minimum 8-character token. Auth is checked at
`server.ts:107-116` **before** the route dispatch, so `/state/import` cannot be reached
unauthenticated and the body is never buffered for an unauthenticated caller. `/health`
is the only unauthenticated route and it discloses only provider/model/uptime —
consistent with the documented design.

**Scheduling privilege escalation — CLEAN.** The unattended context at
`runner.ts:53-65` is fail-closed: `askApproval` returns `false` unless
`BLACKROSE_SCHEDULE_APPROVE=all`, and it deliberately omits `runSubTask`, so
`spawn_agent` and `skill_run` both return "not available"
(`agentTool.ts` / `tools/skills.ts:55`) and cannot be used to launder an approval past
the gate. Approval-gated tools are unreachable from an unattended run.

**Build scripts: shipped secrets, absolute user paths, stale artifacts — CLEAN.**
`desktop/tauri/.gitignore` excludes `core/`, `node/`, `icons/`, `target/`, `gen/`, and
`git check-ignore` confirms `desktop/tauri/core/blackrose.mjs` and
`desktop/tauri/node/node.exe` are ignored — no 800 KB generated bundle or vendored
`node.exe` is committed. The root `.gitignore` excludes `dist/` and `dist-build/`. No
secret is written into any shipped artifact (`tauri.conf.json` contains only the
minisign *public* key). The staleness guard at `build-desktop.ts:165-172` compares the
bundle mtime against the newest file under `src/` and fails closed; I verified both
`dist/blackrose.mjs` and `desktop/tauri/core/blackrose.mjs` are currently newer than the
newest `src/` file and contain the current Executive Brain code. `build-exe.ts:248-265`
validates the produced `.exe` by executing `--doctor` and deletes it if validation
fails. Finding 6 above is about the *key being read*, not about a secret being
shipped — no secret reaches an artifact.

**`desktop/tauri/build.rs` — CLEAN.** The single `.expect("failed to run tauri-build")`
at `build.rs:18` is in a build script, where aborting on failure is the correct
behaviour. No `unwrap()` on runtime state.

**`src/skills/skills.ts` — CLEAN.** `saveSkill` writes only `slug(name) + '.md'`, and
`slug` (`skills.ts:102-103`) strips everything outside `[a-z0-9-_]`, so no traversal.
`loadSkills` wraps each file read in `try` (`skills.ts:110-127`), so one bad skill file
cannot take down the system prompt.

## Notes on accepted risk (not counted as findings)

- The bridge is plain HTTP with the bearer token and, for `/state/import`, the state
  password in an `x-password` header (`bridge/client.ts:100`). Over loopback that is
  fine; `BLACKROSE_BRIDGE_HOST` is the documented opt-in to expose it, called out at
  `server.ts:21-23`. Flagged only so the trade-off stays deliberate.
- `bridge/server.ts:231-238` returns raw exception messages to the caller, which can
  include absolute paths from `importState`'s validator. Authenticated-only, so this is
  information disclosure to an already-trusted caller rather than a boundary crossing.
- `aistate.ts:191` calls `zlib.gunzipSync` with no `maxOutputLength`, so a valid
  (password-known) archive could expand to consume memory. Reaching it requires the
  state password, and the bridge caps the body at 8 MB (`server.ts:81`).
- `writeOne` (`executive.ts:95`) is also used for `saveDecision`, but `decision_record`
  mints its own id via `makeId` (`tools/goals.ts:204`), so decisions are not reachable
  from poisoned file contents the way goals are.
const blob = fs.readFileSync(delta.path)
fs.rmSync(delta.path, { force: true })
```

Two `/state/export` requests inside one second write the same path; the first deletes
the file the second is about to read, so one client can receive the *other* client's
delta or a 500. `bridge/client.ts:92-94` has the same read-then-delete on the pushing
side, which additionally destroys the local delta before the POST completes.

Fix: include a random suffix (`crypto.randomBytes(4).toString('hex')`) in the stamp.

Impact: this key is the root of trust for the auto-updater — the public half is baked
into `tauri.conf.json:47`. Anything that can get code execution as this user and run
`npm run build:desktop` (for example an agent-approved `run_command`) can obtain it and
sign updates the installed app will accept. Turning a build script into a key-access
capability is a privilege escalation the UI never surfaces.

Fix: require an explicit opt-in (e.g. a `--sign` flag or `TAURI_SIGNING_PRIVATE_KEY_PATH`
set by the caller) and print a loud warning when the key is about to be used.
return now.getHours() > h || (now.getHours() === h && now.getMinutes() >= m)  // LOCAL time
```

The "already ran today" guard compares **UTC** dates while the fire time is compared
in **local** time. Whenever the local date and the UTC date disagree, the guard stops
protecting the task and the "already ran" comparison rolls over mid-day.

Reproduced for `dailyAt: "01:30"` in Asia/Kolkata (+05:30):

```
local 03/09/2026 01:30  utc 2026-09-02T20:00Z  due true    <- intended run
local 03/09/2026 06:00  utc 2026-09-03T00:30Z  due true    <- SECOND run, same day
```

Impact: an unattended task — the one class of task with no human watching — executes
twice per local day in every non-UTC timezone, roughly 4-5 h apart. For a task that
posts, sends or installs, that is a duplicate side effect.

Fix: compute `today` from local time (`now.toLocaleDateString('en-CA')`) so both sides
of the comparison use the same clock.
Reproduced end to end:

```
goal_seed.json  ->  { "id": "../../../../.audit-exec/PWNED", ... }
goal_update({ id: "../../../../.audit-exec/PWNED", status: "paused" })
tool said: ../../../../.audit-exec/PWNED → paused [p3] x
ESCAPED FILE WRITTEN: true
parent listing: [ 'goals', 'PWNED.json' ]
```

Impact: a file written at an arbitrary path relative to the goals directory, with
model-influenced JSON content, on every subsequent goal update. `removeOne`
(`executive.ts:137-145`) is *not* affected — it resolves through `readdirSync`, so it
stays inside the directory.

Fix: validate `rec.id` against `/^[A-Za-z0-9_-]+$/` in `writeOne` (the same guard
`session/history.ts:137` and `:150` already use), and reject ids containing `..`.