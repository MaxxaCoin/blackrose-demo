"""NEXT WORK item 9 (exit hang): /exit must drain while the Telegram watch is on.

Edits: (1) TelegramClientOptions grows `signal`, telegramGetUpdates forwards
it; (2) startTelegramWatch owns an AbortController, aborts it in stop();
(3) src/index.ts stops the watch on BOTH exit paths (one-shot + REPL end).
Plus the regression test in telegram.test.ts.
"""
import sys

P = r'src\tools\telegram.ts'
c = open(P, 'rb').read().decode('utf-8')


def rep(old, new, label):
    global c
    n = c.count(old)
    if n != 1:
        print(f'FAIL {label}: found {n}')
        sys.exit(1)
    c = c.replace(old, new)
    print(f'ok {label}')


# 1. TelegramClientOptions grows `signal`
rep(
    "export type TelegramClientOptions = {\r\n"
    "  baseUrl?: string\r\n"
    "}\r\n",
    "export type TelegramClientOptions = {\r\n"
    "  baseUrl?: string\r\n"
    "  /** Abort the in-flight request. The watch's stop() uses it to cut a\r\n"
    "   *  pending long poll, so /exit can drain (2026-10-26, NEXT WORK item 9)\r\n"
    "   *  instead of waiting out the 30s long-poll window (or a stalled socket). */\r\n"
    "  signal?: AbortSignal\r\n"
    "}\r\n",
    'client options signal')

# 2. telegramGetUpdates forwards the signal into the fetch
rep(
    "    const res = await fetchNoTimeout(url)\r\n",
    "    const res = await fetchNoTimeout(url, opts.signal ? { signal: opts.signal } : undefined)\r\n",
    'getUpdates signal')

# 3. the watch owns an AbortController next to `stopped`
rep(
    "  const deliver = opts.deliver ?? deliverTelegramMessage\r\n"
    "  let stopped = false\r\n",
    "  const deliver = opts.deliver ?? deliverTelegramMessage\r\n"
    "  let stopped = false\r\n"
    "  // 2026-10-26 NEXT WORK item 9: /exit drains naturally (no process.exit),\r\n"
    "  // so stop() must cut the in-flight long-poll fetch - a ref'd socket would\r\n"
    "  // otherwise hold the event loop alive for the rest of the window.\r\n"
    "  const pollAbort = new AbortController()\r\n",
    'watch abortcontroller')

# 4. the long poll carries the signal
rep(
    "      const r = await telegramGetUpdates(token, { ...(opts.client ?? {}), offset })\r\n",
    "      const r = await telegramGetUpdates(token, { ...(opts.client ?? {}), offset, signal: pollAbort.signal })\r\n",
    'poll signal')

# 5. an abort on the way out is not a failure - keep shutdown quiet
rep(
    "      if (r.error) {\r\n"
    "        opts.onEvent?.(`  ⚠ telegram watch failed: ${r.error}`)\r\n"
    "        return false\r\n"
    "      }\r\n",
    "      if (r.error) {\r\n"
    "        // A stop() abort lands here as an error; on the way out that is\r\n"
    "        // noise, not a watch failure (2026-10-26, NEXT WORK item 9).\r\n"
    "        if (!stopped) opts.onEvent?.(`  ⚠ telegram watch failed: ${r.error}`)\r\n"
    "        return false\r\n"
    "      }\r\n",
    'quiet on stop')

# 6. stop() cuts the in-flight poll
rep(
    "    stop: () => {\r\n"
    "      stopped = true\r\n"
    "      companionLoopLive = false\r\n"
    "      telegramWatchWake = null\r\n"
    "      release?.()\r\n"
    "      roleLock.lock.release()\r\n"
    "    },\r\n",
    "    stop: () => {\r\n"
    "      stopped = true\r\n"
    "      companionLoopLive = false\r\n"
    "      telegramWatchWake = null\r\n"
    "      release?.()\r\n"
    "      roleLock.lock.release()\r\n"
    "      pollAbort.abort() // cut the in-flight long poll: the event loop can drain\r\n"
    "    },\r\n",
    'stop aborts poll')

open(P, 'wb').write(c.encode('utf-8'))
print('TELEGRAM EXIT FIX APPLIED')

# ---- src/index.ts: stop the watch on both exit paths -----------------------
P2 = r'src\index.ts'
c = open(P2, 'rb').read().decode('utf-8')

rep(
    "    if (goalFlag) await runGoalCommand(oneShot)\r\n"
    "    else await execute(oneShot)\r\n"
    "    scheduler.stop()\r\n",
    "    if (goalFlag) await runGoalCommand(oneShot)\r\n"
    "    else await execute(oneShot)\r\n"
    "    // 2026-10-26 NEXT WORK item 9: the watch loop re-issues long polls\r\n"
    "    // forever; its in-flight ref'd sockets would keep the process alive\r\n"
    "    // after main() returned. Same lifecycle the web UI host applies.\r\n"
    "    telegramWatch?.stop()\r\n"
    "    scheduler.stop()\r\n",
    'one-shot exit stops watch')

rep(
    "    rl.prompt()\r\n"
    "  }\r\n"
    "  scheduler.stop()\r\n"
    "  rl.close()\r\n"
    "}\r\n",
    "    rl.prompt()\r\n"
    "  }\r\n"
    "  telegramWatch?.stop() // cut the long poll so the event loop can drain\r\n"
    "  scheduler.stop()\r\n"
    "  rl.close()\r\n"
    "}\r\n",
    'repl exit stops watch')

open(P2, 'wb').write(c.encode('utf-8'))
print('INDEX EXIT FIX APPLIED')

# ---- regression test --------------------------------------------------------
P = r'src\tools\telegram.test.ts'
c = open(P, 'rb').read().decode('utf-8')

rep(
    "import assert from 'node:assert/strict'\r\n"
    "import fs from 'node:fs'\r\n"
    "import os from 'node:os'\r\n",
    "import assert from 'node:assert/strict'\r\n"
    "import fs from 'node:fs'\r\n"
    "import http from 'node:http'\r\n"
    "import os from 'node:os'\r\n",
    'http import')

rep(
    "test('one watch per data dir: stopping the owner frees the role for the next host', () => {\r\n",
    "// ---------------------------------------------------------------------------\r\n"
    "// 2026-10-26 NEXT WORK item 9: /exit must drain while the watch is on. stop()\r\n"
    "// must cut the in-flight long poll (AbortController), or the ref'd fetch\r\n"
    "// socket keeps the event loop alive for the rest of the 30s window - or\r\n"
    "// forever on a stalled socket.\r\n"
    "// ---------------------------------------------------------------------------\r\n"
    "test('stop() aborts an in-flight long poll so the process can drain', async () => {\r\n"
    "  // A Bot API server that accepts getUpdates and NEVER answers: exactly the\r\n"
    "  // shape that used to wedge the process after /exit (fetchNoTimeout has no\r\n"
    "  // deadline and nothing aborted it).\r\n"
    "  let closeResolve: (() => void) | null = null\r\n"
    "  const closed = new Promise<void>((resolve) => { closeResolve = resolve })\r\n"
    "  let requestResolve: (() => void) | null = null\r\n"
    "  const requested = new Promise<void>((resolve) => { requestResolve = resolve })\r\n"
    "  const srv = http.createServer((req) => {\r\n"
    "    requestResolve?.()\r\n"
    "    req.on('close', () => closeResolve?.())\r\n"
    "    // deliberately never respond - the long poll just hangs\r\n"
    "  })\r\n"
    "  await new Promise<void>((resolve) => srv.listen(0, '127.0.0.1', () => resolve()))\r\n"
    "  const baseUrl = `http://127.0.0.1:${(srv.address() as import('node:net').AddressInfo).port}`\r\n"
    "  const ctx = { dataDir: tmpDataDir(), cwd: tmpDataDir() }\r\n"
    "  saveTelegramToken(ctx.dataDir, '123456:TEST-TOKEN-NOT-REAL')\r\n"
    "  const handle = startTelegramWatch({ dataDir: ctx.dataDir, cwd: ctx.cwd, client: { baseUrl } })\r\n"
    "  try {\r\n"
    "    // Wait until the long poll is actually in flight, then stop: the abort\r\n"
    "    // must close the request within 500ms. Against the old code the socket\r\n"
    "    // stays open forever and the race below times out.\r\n"
    "    await Promise.race([requested, new Promise((_, rej) => setTimeout(() => rej(new Error('watch never issued a getUpdates request')), 2000))])\r\n"
    "    handle.stop()\r\n"
    "    await Promise.race([closed, new Promise((_, rej) => setTimeout(() => rej(new Error('pending long poll was NOT aborted within 500ms')), 500))])\r\n"
    "  } finally {\r\n"
    "    srv.close()\r\n"
    "  }\r\n"
    "})\r\n"
    "\r\n"
    "test('one watch per data dir: stopping the owner frees the role for the next host', () => {\r\n",
    'abort test')

open(P, 'wb').write(c.encode('utf-8'))
print('TEST APPLIED')
