"""Handoff: tier-4 note (release follow-ups closed)."""
import sys

P = r'C:\Users\pc\Desktop\BlackRose\cline\blackrose\docs\08-SESSION-HANDOFF.md'
c = open(P, 'rb').read().decode('utf-8').replace('\r\n', '\n')

ANCHOR = "> **2026-10-26 (tier 3) — NEXT WORK 8, 9, 10 CLOSED (321ff57..c1df5d2).**"
assert c.count(ANCHOR) == 1

NOTE = """> **2026-10-26 (tier 4) — THE RELEASE FOLLOW-UP LIST IS EMPTY (44e09df..15b8993).**
> Closed, each with a test that provably fails against the old code where the
> behaviour is observable: (1) the bundler's subpath-specifier hazard — 46 latent
> `node:assert/strict` imports converted (all of them; none was in the bundle
> graph), plus an emit-time scan in build-exe.ts that NAMES a `node:x/y` the way
> `node --check` only ever reported as a bare SyntaxError; real build verified
> (127 modules, --doctor ok). (2) liveConns hygiene — a self-exited MCP child now
> fires `onDeath` once and every registry reaps its own entry with an identity
> check, so `isConnected`/`listServers` stop advertising a corpse. (3) DNS
> rebinding — the guard's validated IPs are PINNED to the connect via an
> http(s) `lookup` hook (the pre-fix exploit was reproduced live: learn_url
> delivered a loopback page while the guard saw a public IP); the URL keeps its
> hostname form for TLS, and the owner's allowLoopbackFetch path is unchanged and
> separately pinned. (4) atomic writers — 14 sites / 12 modules now use
> `core/atomicFile.ts`; graph.ts and vault.ts are deliberately excluded with
> in-code reasons. The unification's new concurrency test found TWO real helper
> defects, both fixed: `pid+Date.now` temp names collide for same-millisecond
> async writers (ENOENT), and Windows renames fail transiently EPERM/EACCES/EBUSY
> (bounded retry added).
>
> NEWLY FLAGGED, NEEDS THE OWNER: `web_fetch` still plain-fetches arbitrary URLs
> with redirect-following and NO SSRF guard — same class as the rebinding hole,
> larger surface. Not changed silently because it would also block legitimate
> local-dev fetches. Gates: tsc 0, SMOKE PASSED, 427/427, scan clean of real
> values (17 `assigned_secret` fingerprints, all identifiers/calls/env refs),
> verify:checkpoint PASS.
>
"""

c = c.replace(ANCHOR, NOTE + ANCHOR, 1)
open(P, 'wb').write(c.replace('\n', '\r\n').encode('utf-8'))
print('HANDOFF TIER-4 NOTE ADDED')
