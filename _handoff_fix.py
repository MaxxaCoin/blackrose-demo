"""Handoff doc updates for the tier-3 block (items 8, 9, 10 closed)."""
import sys

P = r'cline\blackrose\docs\08-SESSION-HANDOFF.md'
c = open(P, 'rb').read().decode('utf-8')


def rep(old, new, label):
    global c
    n = c.count(old)
    if n != 1:
        print(f'FAIL {label}: found {n}')
        sys.exit(1)
    c = c.replace(old, new)
    print(f'ok {label}')


rep(
    "# 08 — SESSION HANDOFF (read this FIRST)\r\n"
    "\r\n"
    "Originally written 2026-10-05 by the session that shipped v0.9.21;",
    "# 08 — SESSION HANDOFF (read this FIRST)\r\n"
    "\r\n"
    "> **2026-10-26 (tier 3) — NEXT WORK 8, 9, 10 CLOSED (321ff57..c1df5d2).** Item 8:\r\n"
    "> one Telegram watch per data dir (instanceLock role `telegram-watch`, second\r\n"
    "> host gets a reason, dead-owner takeover). Item 9: `/exit` drains while the\r\n"
    "> watch is on (host stops the watch on both exit paths + AbortController cuts\r\n"
    "> the in-flight long poll; the abort test wedges the whole test process against\r\n"
    "> the old code — self-demonstrating), bridge client calls bounded (10 min,\r\n"
    "> `BLACKROSE_BRIDGE_TIMEOUT_MS`), SEA argv double-slice fixed, `/compact` no\r\n"
    "> longer leaves an orphan tool_result at the head (same guard as trimHistory;\r\n"
    "> new smoke checks use real tool blocks), and one persisted vector index = one\r\n"
    "> vector space (stranded re-embed may not cache cross-space; saveStore drops\r\n"
    "> mismatched entries — new `src/memory/vectors.test.ts`). Item 10: `onemin`\r\n"
    "> removed from the LIVE chain — the HKCU env var `BLACKROSE_ROUTES` (env wins\r\n"
    "> over the vault chain; the vault chain was already clean). The adapter stays.\r\n"
    "> `kilo` is also a dead name in that env chain (no adapter) but the factory\r\n"
    "> skips it before any network call — owner's call to prune. Gates: tsc 0,\r\n"
    "> SMOKE PASSED (HKCU env merged; bare host still fails the same 4 known\r\n"
    "> machine-dependent checks), 403/403, scan:secrets clean\r\n"
    "> (`validation/gate-item9-block.out`).\r\n"
    "\r\n"
    "Originally written 2026-10-05 by the session that shipped v0.9.21;",
    'handoff top note')

rep(
    "8. **`src/tools/telegram.ts` — one Telegram watch per data dir.** Two hosts both\r\n"
    "   long-poll `getUpdates` on the same bot token (409s, split or duplicated\r\n"
    "   updates). Take an `instanceLock` role `telegram-watch` when the watch starts.\r\n"
    "9. **Small correctness batch:** vectors must not persist a mixed 3072/256-d\r\n"
    "   index; `/compact` must not leave an orphan `tool_result` at the head;\r\n"
    "   `mastery`/`experiment`/constitution write truncate-then-write — **DONE 2026-10-26 (`2386a9c`)**; SEA argv\r\n"
    "   is sliced twice; `/exit` can hang while the Telegram watch is on; bridge client\r\n"
    "   calls have no timeout.\r\n"
    "10. **Housekeeping:** delete or replace the `onemin` route in the chain — its key\r\n"
    "    is inactive (doctor: HTTP 401, \"API key is not active\"), so every failover\r\n"
    "    past it costs a round trip.",
    "8. **DONE 2026-10-26 (`321ff57`: instanceLock role `telegram-watch`, refusal with a reason, dead-owner takeover + 2 tests).** **`src/tools/telegram.ts` — one Telegram watch per data dir.** Two hosts both\r\n"
    "   long-poll `getUpdates` on the same bot token (409s, split or duplicated\r\n"
    "   updates). Take an `instanceLock` role `telegram-watch` when the watch starts.\r\n"
    "9. **Small correctness batch — DONE 2026-10-26:** vectors no longer persist a\r\n"
    "   mixed 3072/256-d index (`c1df5d2`); `/compact` cannot leave an orphan\r\n"
    "   `tool_result` at the head (`bbd5523`);\r\n"
    "   `mastery`/`experiment`/constitution write truncate-then-write — **DONE 2026-10-26 (`2386a9c`)**; SEA argv is sliced twice — **DONE (`321ff57`)**; `/exit` can hang while\n"
    "   the Telegram watch is on — **DONE (`321ff57`)**; bridge client\r\n"
    "   calls have no timeout — **DONE 2026-10-26 (`ac7991d`)**.\r\n"
    "10. **DONE 2026-10-26 (data-side, no code change).** **Housekeeping:** delete or replace the `onemin` route in the chain — its key\r\n"
    "    is inactive (doctor: HTTP 401, \"API key is not active\"), so every failover\r\n"
    "    past it costs a round trip. Removed from the HKCU `BLACKROSE_ROUTES` chain\r\n"
    "    (broadcast sent; vault chain was already clean); the adapter code stays for\r\n"
    "    a working key. `kilo` flagged as a second dead name — costs a warning, not\r\n"
    "    a round trip; left for the owner.",
    'NEXT WORK 8-10')

open(P, 'wb').write(c.encode('utf-8'))
print('HANDOFF UPDATED')
