# BlackRose 0.11.0

38 commits since v0.10.2. The theme is **things that were quietly wrong now fail loudly, or not at all**.

## Security

- **`web_fetch` is SSRF-guarded.** It took an arbitrary model-chosen URL and plain-fetched it with
  redirects followed and no guard at all, while `learn_url` next door was already guarded. Both now
  share one implementation (`src/core/publicFetch.ts`): manual redirects, every hop resolved and
  checked, connect pinned to the validated addresses. Loopback only through an owner capability
  (`ctx.allowLoopbackFetch` or `BLACKROSE_FETCH_ALLOW_LOOPBACK=1`), never through tool input.
- **DNS rebinding is dead.** The guard's lookup and the socket's connect were two independent
  resolver queries; attacker DNS with TTL 0 could answer public to the guard and private to the
  socket. The connect is pinned to the validated array, so there is no second query to poison.
- **Atomic writes everywhere.** 14 hand-rolled writers (budget, cost meter, policy, workflow,
  instance lock, plugins, custom tools, self-improve, mcp.json, vectors, history, schedules, undo,
  knowledge) now go through `core/atomicFile.ts`, with fsync, cleanup on failure, a unique temp name
  and a bounded retry for Windows' transient EPERM. A crash mid-write no longer truncates state.

## Fixed

- **M9 — a dead embedding key cost 29 s per batch.** The per-key retry ladder was replayed on the
  key that had just failed instead of rotating. `attemptWithKey` now separates key-independent
  failures (404, malformed body → stop, fall back honestly) from per-key ones (every other 4xx →
  rotate once). Measured 6 calls / 29.1 s → 2 calls / 0.1 s, pinned by two tests that fail on the
  old code.
- **M6** an exhausted scheduled run now backs off and disables after 5 resumes instead of looping
  forever; **M7** `--resume` picks the newest *updated* session, not the newest created.
- **L6** two skill names can no longer collapse to one file; **L7** XLSX sheets sort numerically;
  **L8** UI sessions compact themselves instead of growing without a cap.
- Bridge client calls are bounded (a hung host no longer wedges the caller); one Telegram watch per
  data dir and `/exit` can drain while it runs; `/compact` can no longer leave an orphan
  `tool_result` at the head; a self-exited MCP child stops being advertised as connected; the undo
  journal's blob GC cannot eat an in-flight snapshot; `apply_change` refuses a stale sandbox; the
  budget ledger is a real cross-process critical section; adapters read the HTTP status before
  parsing the body (a dead key parks instead of burning a request per turn); path-scoped policy
  rules apply to `run_command`; and a mixed 256/3072-d vector index can no longer reach disk.

## New

- **Brain viewer (queue row 138)** — 🧠 in the sidebar. Four read-only routes (`/api/brain/sources`,
  `/source`, `/graph`, `/health`) over the knowledge store, the entity graph and the vector index.
  The health strip shows the embedder's own `degraded` verdict next to the store's dim/model and a
  "chunks with no vector" count — the mismatch that silently downgrades retrieval to keyword-only.
  The graph is an inline SVG force layout: deterministic, no library, no random seed.
- **Retrieval eval gate** — 12 documents / 20 query pairs, run as a blocking test in `npm test`.
- **Oxion provider preset** — one key across 33 ids (Claude Sonnet 5 / Opus 5.5, GPT-5.6, Gemini 3.1
  Pro, DeepSeek V4, Qwen 3.8, Kimi K3, GLM 5.3).

## Configuration

- **Gemini's default model was retired upstream.** `gemini-2.5-flash` returns 404 and the API names
  `gemini-3.8-flash` as its replacement; the shipped default is updated so a fresh install does not
  fail with a model error that reads like a bad key.

## Verified

`tsc --noEmit` 0 · `SMOKE TEST PASSED` · **419/419** `node --test` · `scan:secrets` clean (every
fingerprint read and classified) · `verify:checkpoint` PASS · `build:exe` 128 modules, syntax ok,
`--doctor` ok.

## Notes

- The updater key's password is short and guessable, and rotating it breaks every installed client.
  Do not rotate casually.
- Open: audit M8 (`.aistate` inflate cap) and L1–L5; queue rows 137 and 139; three owner decisions
  (`mini.ts` constitution default, fail-closed approvals, the `kilo` route with no adapter).
