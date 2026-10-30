# Investigation: `/exit` hangs while the Telegram watch is on

Read-only investigation of `cline/blackrose` (working tree, incl. uncommitted NEXT WORK item 8 changes). Date: 2026-10-26. No files under `src/` were modified.

## 1. Exact mechanism of the hang

**Primary keeper — the in-flight long-poll fetch.**
- `src/tools/telegram.ts:2314-2341` — `loop()` is `while (!stopped) { … await poll() … }`. `stopped` is only ever set inside the handle's `stop()` (`src/tools/telegram.ts:2349`), which **nothing in `src/index.ts` ever calls**.
- `src/tools/telegram.ts:2287` — `const r = await telegramGetUpdates(token, { ...(opts.client ?? {}), offset })`.
- `src/tools/telegram.ts:371` → `src/tools/telegram.ts:319-321` — `fetchNoTimeout()`: a plain `fetch(url, …)` with **no timeout and no AbortSignal** (its own comment: "Fetch with NO time limit"). The URL carries the Bot API long-poll window `&timeout=30` (`src/tools/telegram.ts:369`).
- While that request is in flight, its undici/TCP socket is a **ref'd** handle: it keeps the Node event loop alive even after `main()` has resolved. And when the 30 s window ends, `while (!stopped)` immediately issues the next long poll — so the process never reaches a quiet event loop.

**Secondary keepers (same loop, failure path):**
- `src/tools/telegram.ts:2334` — `await sleep(5_000)` after a failed poll; `sleep()` (`~:2223`) holds a **ref'd** `setTimeout` while pending, then the loop re-polls.

**Ruled out (all unref'd or harmless):**
- Role-lock heartbeat: `src/core/instanceLock.ts:113` — `timer.unref?.()`.
- Typing loop: `src/tools/telegram.ts:1069` — `timer.unref?.()`.
- `park()` (`telegram.ts:~2233`): a timer-less pending promise — does not keep the loop alive (so a *token-less* parked watch alone would NOT hang the process; the hang needs a configured token).
- readline: `rl.close()` is called on `/exit` (`src/index.ts:953`); scheduler is stopped (`src/index.ts:952`). Neither is the keeper.

## 2. How `/exit` currently terminates — and why the watch defeats it

`/exit` (`src/index.ts:784`) just `break`s the `for await (const line of rl)` loop; the trailing code (`src/index.ts:952-953`) is `scheduler.stop(); rl.close()` and then `main()` returns — **natural drain, no `process.exit`** (the only `process.exit` calls are the fatal-error paths). Drain works when nothing holds a ref'd handle. The watch defeats it because (a) its loop keeps re-issuing the long-poll fetch forever (`stopped` never set), and (b) each fetch's in-flight socket is ref'd. Note `src/index.ts:766` (one-shot mode) has the same bug: `startTelegramWatch` runs at `src/index.ts:668` *before* the one-shot branch, which then does `scheduler.stop(); rl.close(); return` — never stopping the watch.

**Precedent that this is a host-lifecycle gap, not the watch's design:** the web UI host does it right — `src/ui/web/main.ts:412-413` registers `watch.stop()` on SIGINT/SIGTERM, and `src/ui/web/main.ts:227` hard-exits with `process.exit(0)`.

## 3. Minimal fix (codebase style)

**(a) `src/index.ts` — call the handle's stop on every exit path (2 lines):**
- One-shot path (~line 766): add `telegramWatch?.stop()` next to `scheduler.stop()`.
- REPL end (~line 952): add `telegramWatch?.stop()` next to `scheduler.stop()`.

This is exactly the web-UI pattern (`main.ts:412-413`). `stop()` (`telegram.ts:2348-2354`) sets `stopped = true`, clears `telegramWatchWake`, wakes `release?.()`, and **releases the role lock synchronously**: `roleLock.lock.release()` (`telegram.ts:2353`) → `src/core/instanceLock.ts:142-156` (clearInterval of the heartbeat + `fs.rmSync` of the lock file when still ours). So the lock is never orphaned and a second host is never wedged — same guarantee the item 8 test 'stopping the owner frees the role' already asserts.

**(b) `src/tools/telegram.ts` — make `stop()` cut the in-flight poll (≈4 lines):** `stop()` alone leaves the current long poll pending, so the process still hangs up to the 30 s window — or indefinitely if the socket stalls (`fetchNoTimeout` has no timeout). Wire an abort:
```ts
// in startTelegramWatch, near `let release: …`
const ac = new AbortController()
// in poll(): pass it through — fetchNoTimeout already accepts RequestInit (telegram.ts:319)
const r = await telegramGetUpdates(token, { ...(opts.client ?? {}), offset, signal: ac.signal })
// in stop():
ac.abort()
```
`TelegramClientOptions` gains an optional `signal`, `telegramGetUpdates` forwards it in the `init` handed to `fetchNoTimeout` (add `signal: opts.signal` to the fetch call at `telegram.ts:371`). Aborting rejects the pending fetch → `poll()` catches → `loop()` sees `stopped` → loop returns → event loop drains and the process exits naturally. No `process.exit` fallback needed; no lock orphaned (release already ran synchronously before drain).

**Why not bare `process.exit(0)` on `/exit`:** it works (a dead owner's lock is auto-taken-over via the pid check, `instanceLock.ts:100-104`), but it skips the graceful `stop()` path the web UI uses and is unnecessary once (a)+(b) exist.

## 4. Regression test

**File:** `src/tools/telegram.test.ts` (co-located node:test file, fake Bot API style — no live api.telegram.org, per the module's contract).

**Test:** "stop() aborts an in-flight long poll — the process can drain". Start a local `http.createServer` that accepts `getUpdates` and **never responds**; point the watch at it via `{ client: { baseUrl } }` (the same opt the fake-server tests use). Then:
1. wait one tick (a request arrived),
2. `handle.stop()`,
3. assert the client socket closed / the request aborted within, say, 500 ms (e.g. resolve a promise from the server's `'close'`/`'aborted'` event on that request), and assert no second `getUpdates` request follows.

**Why it fails against current code:** with no AbortController, `stop()` only flips `stopped`; the pending `fetchNoTimeout` socket against a never-responding server stays open forever — the close-abort assertion times out. (The role-lock half of the fix is already covered by the existing item 8 test `'one watch per data dir: stopping the owner frees the role for the next host'`, `src/tools/telegram.test.ts:417-428`.)

## Evidence tiers
- **Verified (one-hand code):** all `file:line` citations above, read from the current working tree.
- **Verified (test):** existing item-8 tests at `src/tools/telegram.test.ts:396-428`.
- **Inference (high confidence):** undici in-flight sockets keep the event loop alive — standard Node behavior, consistent with the observed hang; not separately reproduced here (read-only run).
- **Not checked:** whether `scheduler.stop()` clears all its timers; irrelevant to this bug since the scheduler is stopped on `/exit`.
