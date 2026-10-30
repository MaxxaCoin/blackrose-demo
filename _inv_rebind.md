# Investigation: DNS-rebinding residual in BlackRose `fetchPublicUrl`

Repo: `C:\Users\pc\Desktop\BlackRose\cline\blackrose` — Node 24 (v24.20.0 confirmed), zero runtime deps (`package.json` has only devDependencies: typescript, @tauri-apps/cli, @types/node).
Residual as recorded: `docs/BLACKROSE_CHECKPOINT.txt:270` — "DNS rebinding between lookup and fetch is still open (needs connect-time IP pinning) - documented residual, not a trivial bypass anymore"; also `docs/08-SESSION-HANDOFF.md:47` ("Open follow-ups: DNS-rebinding residual").

---

## 1. Call sites and what happens between check and connect

### Call sites of `fetchPublicUrl` / the private-IP guard

| Site | What it guards |
|---|---|
| `src/tools/knowledge.ts:383` — `loadIngestText()` | `knowledge_ingest` with a URL target (approval-gated tool; the `ingestItem` engine) |
| `src/tools/knowledge.ts:1160` — `learn_url` tool `run()` | `learnUrlTool`, callable by the model |

Both route through `fetchPublicUrl` (knowledge.ts:312), which per hop:
1. rejects literal private/numeric hosts via `PRIVATE_HOST_RE` (knowledge.ts:269) and a `/^\d+$/`/hex/`[` literal check (knowledge.ts:334),
2. resolves with `dns.promises.lookup(host, { all: true, verbatim: true })` (knowledge.ts:337) and refuses if ANY address is private via `isPrivateAddress` (knowledge.ts:279-300),
3. calls `fetchWithTimeout(u, { redirect: 'manual' })` (knowledge.ts:344) → `fetch()` in `src/tools/web.ts:19` (global undici fetch).

`isPrivateAddress` is also directly tested in `src/audit-sweep2.test.ts:111`.

Adjacent finding (out of scope, flagged): `src/tools/web.ts:40` (`web_fetch`) has **no** SSRF guard at all — plain `fetch` with redirect-following on arbitrary URLs. Same class, larger hole than the recorded residual. (Noted, not fixed — out of scope per the read-only brief.)

### What Node does between the check and the connect

- The check (knowledge.ts:337) and the connect are **two independent DNS queries**. `dns.promises.lookup` goes to the OS `getaddrinfo` (Node docs, dns module: "dns.lookup() ... uses the underlying operating system facilities ... getaddrinfo(3)"). An attacker-authoritative DNS server with TTL 0 can answer differently per query.
- Global `fetch` in Node is undici's fetch. **Node docs / undici do not expose any `lookup`-style option on `fetch`'s RequestInit** — undici issue #421 ("Feature request: allow a custom dns lookup function to be [used in fetch]", nodejs/undici#421) confirms custom lookup is *not* available on fetch and suggests the undici Agent route instead.
- At TCP connect, undici calls `net.connect`/`tls.connect`, whose default `lookup` is `dns.lookup` — a **second, independent getaddrinfo call** (verified empirically in this run: patching `dns.lookup` redirects fetch's connect resolution; probe output "[dns.lookup called] localhost." under a patched hook).
- Node ≥20 defaults `autoSelectFamily: true` on `net.connect` (Happy Eyeballs; nodejs/node issue #52216 confirms the default flipped in 20.0.0; nodejs.org/api/net.html lists the option and its autodetection algorithm). With a multi-A/AAAA answer, connect may try **any** of the returned addresses in sequence — so even a single query returning `[public, private]` can pass the guard (it only needs ONE bad address to refuse, but a public-only first answer plus a rebound second query, or a mixed multi-A answer ordered public-first, both connect privately).
- **Net effect: the validated answer is never bound to the socket.** Node's fetch has no built-in way to pin it (no `lookup` option, no dispatcher option without the undici package — and `require('undici')` fails in this repo, confirmed: `Cannot find module 'undici'`, Node 24.20.0). The repo's zero-dep constraint rules out adding it via npm.

---

## 2. Remediation options, ranked for a zero-dependency Node 24 app

### R1 — Custom `lookup` hook on `node:http`/`node:https` (RECOMMENDED)
Replace the `fetchWithTimeout` call inside `fetchPublicUrl` (knowledge.ts:344) with a `http.request`/`https.request` that receives a `lookup` option. `http.request` passes `lookup` down to `net.connect`/`tls.connect` (Node docs, http.request options → net.connect options). The hook closes over the already-validated address list (from the same `dns.promises.lookup` at knowledge.ts:337) and returns only those — **connect never re-resolves**.
- **Cost**: ~40–60 lines — replace one `fetch` with a request wrapper, convert the `IncomingMessage` to a `Response` (Node's global `Response` accepts a web `ReadableStream` body; `node:stream`.Readable.toWeb bridges it). Per-hop manual redirect loop already exists. Timeout via `req.setTimeout`/destroy.
- **Residual risk after fix**: DNS rebinding (TOCTOU) and multi-A hop-picking are both closed — validation and connect consume the same address array. Remaining gaps are unchanged from the current guard: `isPrivateAddress` doesn't list multicast (224.0.0.0/4, ff00::/8), 198.18.0.0/15, 192.0.2.0/24 (TEST-NET), broadcast — none are useful SSRF targets today, worth a one-line audit note.

### R2 — Post-connect socket validation
After the request connects, inspect `req.socket.remoteAddress` and destroy if it's private. Cheapest change, but the request is **already on the wire** when checked — TLS handshake and the HTTP request line/headers already reached the internal service, so it degrades an exfil to a stateless probe. Useful only as defense-in-depth layered on R1.

### R3 — Resolver cache pinned per request
Resolve once, cache the answer, and force the connect to that IP by rewriting the URL to `http://<ip>/...` with an explicit `Host:` header. Breaks for https: undici's TLS SNI and cert check would then run against the IP, not the original hostname — there is no way to pass `servername` through global fetch (undici #421). Workable for http-only sources; not a general fix.

### R4 — undici Agent with `connect: { lookup }` + pinned IP + Host header
The textbook fix (undici Agent supports a custom `connect.lookup`), but it requires the undici package (or Node's bundled-but-unexported copy) — **violates the zero-dep constraint**. Worth it only if the constraint is ever relaxed.

---

## 3. Recommended minimal fix (builtins only)

Swap knowledge.ts:344's `fetchWithTimeout(u, { redirect: 'manual' })` for a `guardedRequest(u, validatedAddrs)` that uses `http.request`/`https.request` with the pinned `lookup` hook from R1. The existing `dns.promises.lookup` at knowledge.ts:337 becomes the *single* resolution point; the validated addresses are handed to the connect and never re-queried. (Verified working in `validation/scratch-rebind/fix-demo.mjs` — with the hook, the connect went to the validated public IP and the loopback server was never reached, even though the OS resolver would have said 127.0.0.1.)

## 4. Regression test design

Two files, both in `validation/scratch-rebind/`, both driven with real code, no src/ edits:

- `repro.mjs` — **exploit demo (PASSED, exploit confirmed)**: starts an "internal" HTTP server on 127.0.0.1:<ephemeral>, patches `dns.promises.lookup` to answer the guard's query for `rebind.attacker.example` with a public IP (93.184.216.34) and `dns.lookup` (the connect-time API) with 127.0.0.1 — exactly the two answers an attacker's TTL-0 authoritative DNS would give. Drives the real `learnUrlTool` (imported from `src/tools/knowledge.ts`) with a scratch ctx. Result on this run:
  - `learn_url` returned `{ isError: false, content: "Learned http://rebind.attacker.example:14698/secret (HTTP 200) → 1 chunk(s)." }`
  - the loopback server logged the hit: `{ url: "/secret", host: "rebind.attacker.example:14698", ua: "Mozilla/5.0 (BlackRose personal assistant)" }`
  - i.e. the guard saw a public IP but the TCP connect landed on loopback. Exploitable in the TOCTOU dimension.
- `probe.mjs` — confirms undici's connect-time hook chain (`net.connect` → `dns.lookup`) is reachable and patchable, and that Node ≥20's `autoSelectFamily` (Happy Eyeballs) makes the connect use a `all:true` array answer.
- `fix-demo.mjs` — proves the R1 hook: with a `lookup` option pinned to the validated address, `http.request` connects to 93.184.216.34 (ETIMEDOUT here — no service there) and never to 127.0.0.1. Rebinding defeated.

To turn `repro.mjs` into a permanent regression test: assert `learnUrlTool.run(...)` returns `isError: true` (or, after R1, that the loopback server records **no** hit) under the same patched-DNS setup.

## 5. Evidence tier summary

| Finding | Evidence | Tier |
|---|---|---|
| Guard resolves/validates before the connect, no pinning | knowledge.ts:337, 344 | 1st-party code |
| Call sites | knowledge.ts:383, 1160 | 1st-party code |
| Residual is recorded, unfixed | BLACKROSE_CHECKPOINT.txt:270, 08-SESSION-HANDOFF.md:38-53 | 1st-party docs |
| Two independent DNS queries (guard vs connect) | repro.mjs run output (above) | 1st-party experiment |
| fetch/undici has no custom-lookup option | nodejs/undici#421 | official issue tracker |
| autoSelectFamily default true, Node ≥20 | nodejs/node#52216, nodejs.org/api/net.html | official docs + issue |
| `http.request` accepts `lookup`, defeating rebinding | fix-demo.mjs experiment | 1st-party experiment |
