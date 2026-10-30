"""NEXT WORK item 8: one Telegram watch per data dir (instanceLock role)."""
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


# 1. import
i = c.find("import { runEmergencyTeardown, formatTeardown } from './emergency.ts'\r\n")
if i == -1:
    # find the actual emergency import line
    import re
    m = re.search(r"import \{[^}]*runEmergencyTeardown[^}]*\} from '\./emergency\.ts'\r\n", c)
    if not m:
        print('FAIL: emergency import not found')
        sys.exit(1)
    old_imp = m.group(0)
else:
    old_imp = "import { runEmergencyTeardown, formatTeardown } from './emergency.ts'\r\n"
rep(old_imp, old_imp + "import { acquireRoleLock } from '../core/instanceLock.ts'\r\n", 'instanceLock import')

# 2. the role lock at watch start
rep(
    "export function startTelegramWatch(opts: TelegramWatchOptions): TelegramWatchHandle {\r\n"
    "  const deliver = opts.deliver ?? deliverTelegramMessage\r\n"
    "  let stopped = false",
    "export function startTelegramWatch(opts: TelegramWatchOptions): TelegramWatchHandle {\r\n"
    "  // 2026-10-26 NEXT WORK item 8: ONE watch per data dir. Two hosts long-polling\r\n"
    "  // getUpdates on the same bot token produce 409 conflicts and split or\r\n"
    "  // duplicated updates, so the watch owns an instanceLock role for its whole\r\n"
    "  // life; a second host gets an inert handle and a REASON, not a second\r\n"
    "  // poller. A dead owner's lock is taken over automatically (pid check), so a\r\n"
    "  // crashed host cannot wedge Telegram off forever.\r\n"
    "  const roleLock = acquireRoleLock(opts.dataDir, 'telegram-watch')\r\n"
    "  if (!roleLock.ok) {\r\n"
    "    opts.onEvent?.(`telegram watch NOT started: ${roleLock.reason} (another BlackRose host owns the watch)`)\r\n"
    "    return { stop: () => {}, runOnce: async () => {} }\r\n"
    "  }\r\n"
    "  const deliver = opts.deliver ?? deliverTelegramMessage\r\n"
    "  let stopped = false",
    'role lock at start')

# 3. release on stop
rep(
    "    stop: () => {\r\n"
    "      stopped = true\r\n"
    "      companionLoopLive = false\r\n"
    "      telegramWatchWake = null\r\n"
    "      release?.()\r\n"
    "    },",
    "    stop: () => {\r\n"
    "      stopped = true\r\n"
    "      companionLoopLive = false\r\n"
    "      telegramWatchWake = null\r\n"
    "      release?.()\r\n"
    "      roleLock.lock.release()\r\n"
    "    },",
    'release on stop')

open(P, 'wb').write(c.encode('utf-8'))
print('TELEGRAM SINGLE-WATCH APPLIED')
