# Security & Bug Audit - `src/llm/`, `src/memory/`, `core/{vault,undo,keystore,keys}.ts`, `src/mcp/`

**Scope:** 12 files in `src/llm/`, 14 in `src/memory/`, `core/vault.ts`, `core/undo.ts`,
`core/keystore.ts`, `core/keys.ts`, `src/mcp/`.
**Method:** read + trace. Every finding cites `file:line`. Reachability was traced from the
exported function to at least one real caller.
**Excluded per instructions:** the `openai2` unreachable-route config issue; the 3 dead Gemini
keys (403 project-denied).

**Verdict in one line:** the secret-handling design is genuinely good (headers only, AES-256-GCM
with an auth tag, no URL-borne keys) - the real defects are **three non-atomic JSON writes that
can silently destroy a rollback point / a key store / an 8000-entry vector index**, an
**unbounded inflate** in both ZIP and PDF extraction, and **two failover-classification bugs**
that park good credentials and re-hammer dead routes.

---

## Severity-ranked summary

| # | Sev | Status | Finding | Location |
|---|-----|--------|---------|----------|
| 1 | **Critical** | CONFIRMED | Vector index saved with a non-atomic whole-file `writeFileSync` - concurrent or interrupted writes destroy the entire index silently | `memory/vectors.ts:198` |
| 2 | **High** | CONFIRMED | `inflateRawSync`/`inflateSync` with no `maxOutputLength` - a 2 MB document decompresses to gigabytes (decompression bomb) | `memory/zip.ts:65`, `memory/pdf.ts:18,24` |
| 3 | **High** | CONFIRMED | HTTP **413** classifies a key as `parked` for 30 minutes - one oversized request disables a working credential | `llm/keyHealth.ts:49,61` |
| 4 | **High** | CONFIRMED | `updateStoredKeys` is a non-atomic read-modify-write - two writers lose a key with no error | `core/keystore.ts:118-125` |
| 5 | **Medium** | CONFIRMED | Undo entry manifests written non-atomically - a crash mid-write silently deletes the rollback point | `core/undo.ts:160` |
| 6 | **Medium** | CONFIRMED | The router never skips a `down` route; every turn pays a full round-trip/timeout for a known-dead gateway | `llm/router.ts:28-41` + `llm/routeHealth.ts:69` |
| 7 | **Medium** | CONFIRMED | Embedding key pool does not rotate on *transient* failures - the ladder is replayed N-times on key[0] | `memory/embedder.ts:218-227,343-346` |
| 8 | **Medium** | CONFIRMED | `anthropicClient` drops the `AbortSignal` entirely - Stop cannot cancel an in-flight Anthropic request | `llm/client.ts:66` |
| 9 | **Low** | CONFIRMED | Anthropic keys are mislabelled `openai_key` in every redaction report (pattern ordering) | `memory/redact.ts:37,39` |
| 10 | **Low** | CONFIRMED | MCP stdio buffer grows without bound if a server never emits a newline | `mcp/client.ts:47` |
| 11 | **Low** | SUSPECTED | `Math.max(...array)` in the hot retrieval path can throw `RangeError` on a very large corpus | `memory/hybrid.ts:76` |

---

## 1 - CRITICAL - CONFIRMED - Vector index destroyed by a non-atomic write

`src/memory/vectors.ts:198`

```ts
fs.writeFileSync(store.path, JSON.stringify(store.file))
```

`index.json` is a single JSON document holding up to `MAX_ENTRIES = 8000`
(`vectors.ts:48,193-196`), each entry a base64 `Float32Array`. The write is a plain
`writeFileSync` - no temp file, no `renameSync`. This is the **only** large state file in scope
that does not use the atomic pattern the codebase already knows about: `core/vault.ts:164-170`
(`writePrivate`) uses tmp+rename, and the undo blob store is content-addressed.

Two reachable failure modes:

1. **Interruption.** `writeFileSync` truncates the file before writing. A crash, a forced quit of
   the desktop app, or a full disk leaves a partial `index.json`. On the next load, `loadStore`
   catches the parse failure (`vectors.ts:73-75`) and returns `rebuilt: true` with an **empty**
   `entries` map. The comment says "first load, corrupt, or model changed -> rebuild" - so
   corruption is silently indistinguishable from a first run, and the entire 3072-d
   `gemini-embedding-001` index is gone. Rebuilding costs one of the 1000/day free-tier embed
   requests per chunk (`memory/embedder.ts:111`).
2. **Concurrency.** Two processes legitimately hold the same `dataDir`: the desktop app
   (`src/index.ts`) and `scripts/warm-embed.ts`, which calls `openStore` -> `vectorsFor` ->
   `saveStore` (`warm-embed.ts:42,100-102`). Both load, both mutate, both save. The second
   `writeFileSync` overwrites the first with a snapshot that does not contain the other's
   additions. There is no lock, no mtime check, no merge.

Note this is *not* the failure the existing `unsafeFallback` guard (`vectors.ts:185-192`)
protects against. That guard stops a *deliberate* lexical-fallback overwrite; it says nothing
about a torn or clobbered write, and in fact `console.warn`s about the wrong thing while the
real loss is silent.

**Fix:** `writePrivate`-style tmp + `renameSync` (atomic for same-directory renames on both NTFS
and POSIX), plus an exclusive lockfile or an mtime-recheck-and-reload before save.

---

## 2 - HIGH - CONFIRMED - Unbounded inflate (decompression bomb) in ZIP and PDF extraction

`src/memory/zip.ts:60-69`

```ts
const raw = b.subarray(dataStart, dataStart + compSize)
...
else if (method === 8) {
  try { out = zlib.inflateRawSync(raw) } catch { out = null }
}
```

`src/memory/pdf.ts:16-27`

```ts
try { return zlib.inflateSync(b) } catch { /* not zlib-framed */ }
try { return zlib.inflateRawSync(b) } catch { /* not raw deflate either */ }
```

Neither call passes `maxOutputLength`. Node's zlib sync APIs accept it and **throw** when the
inflated size exceeds it; omitting it means the output is bounded only by available memory.

The input side *is* bounded, which is what makes this a bomb rather than an unbounded read:
`tools/knowledge.ts:31` sets `MAX_LEARN_BYTES = 2 * 1024 * 1024`, and every document tool checks
it before reading (`knowledge.ts:381,426,454,482,510,538`) as does the folder walk
(`knowledge.ts:304`). But 2 MB is the **compressed** size. Deflate reaches ~1032:1, so a
2 MB `.docx` or `.epub` - trivially constructible - inflates to roughly 2 GB, and `readZip`
inflates **every** entry in the archive (`zip.ts:45-73`), not just the one the caller wants.
A 2 MB zip holding 200 such members allocates ~400 GB before anything is filtered.

`pdf.ts` is worse in one respect: `learn_pdf` falls through to OCR for text-less PDFs
(`knowledge.ts:394-397`), and `tools/ocr.ts:38` raises the PDF ceiling to **50 MB**, so the
inflate path can be fed a 50 MB PDF.

`learn_folder` with `documents:true` reaches all four OOXML/epub extractors in one call
(`knowledge.ts:322-333` -> `extractDocumentText`, `knowledge.ts:170-176`), so a single folder
containing a handful of crafted documents is enough.

`readZip` is a read-only visitor - it never writes to disk - so there is **no path-traversal
vulnerability** on extraction, and `dataStart` overflow is benign (`Buffer.subarray` clamps to
length, producing an empty slice that then fails to inflate and is skipped). Those two sub-risks
are clean; the memory one is not.

**Fix:** pass `maxOutputLength` sized per-entry (e.g. 32 MB) and treat an over-limit entry as a
skipped one, matching the existing "skip rather than throw" policy in the module docstring.

---

## 3 - HIGH - CONFIRMED - HTTP 413 parks a working key for 30 minutes

`src/llm/keyHealth.ts:49`

```ts
if (/40[13]|unauthorized|forbidden|invalid.*(key|token|auth)|authentication|token is invalid/i.test(msg)) {
  return 'parked'
}
```

The character class `[13]` is intended to capture 401 and 403, but `413` - **Payload Too
Large** - is a request-size condition with nothing to do with the credential. It is a routine,
self-inflicted, *transient* failure: one oversized prompt, one long tool-result blob, one
`max_tokens` the gateway dislikes.

The consequence is severe because `parked` is the longest state in the file:
`PARK_COOLDOWN_MS = 30 * 60_000` (`keyHealth.ts:27`), and `keyUsable` returns `false` for the
whole window (`keyHealth.ts:82-88`). `rotatingKeyClient` filters on exactly that
(`llm/router.ts:98`), so for 30 minutes the key is not offered to the router - a perfectly
healthy credential is silently removed from a pool that may hold 13 keys.

This is precisely the failure mode the module docstring (`keyHealth.ts:12-15`) says parking
exists to prevent, inverted: parking should stop a *dead key* from burning requests, not let one
bad request disable a live one.

**Fix:** anchor on the full status code rather than a character class - use `/\b(401|403)\b/` and
treat 413 (and 413-shaped gateway messages) as transient.

---

## 4 - HIGH - CONFIRMED - `updateStoredKeys` is a non-atomic read-modify-write

`src/core/keystore.ts:118-125`

```ts
export function updateStoredKeys(dataDir, mutate) {
  const stored = readStoredKeys(dataDir)   // read
  mutate(stored)                           // modify in memory
  writeStoredKeys(dataDir, stored)         // write everything back
}
```

`readStoredKeys` (`keystore.ts:94-100`) may itself trigger `migratePlaintextKeys`, which does a
`writeVault` + verify + `rmSync` (`keystore.ts:71-88`). So a single logical update can perform
several whole-vault rewrites. There is no lock and no compare-and-swap around the read/write pair.

Callers include `saveKey` (`keys.ts:130-144`) and `removeProviderKey` (`keys.ts:419-436`) - the
two operations that create and delete credentials. Two concurrent callers (two UI requests, or
the desktop app while the bridge writes the provider registry via `core/providers.ts`) both read
state S, each adds or removes its own key, and the second `writeVault` discards the first's
change. **The user loses an API key with no error, no log line, and no way to notice** beyond a
later 401.

The file's own header (`keystore.ts:5-29`) is a post-mortem of exactly this bug class - a writer
that sealed a store containing only its own field. The fix applied there addressed *which store
is read*; it did not address the read-modify-write window itself, so the underlying hazard
remains.

**Fix:** hold an exclusive lock on `dataDir` for the duration of the RMW (the atomic `writePrivate`
rename at `vault.ts:164-170` makes the write half safe; only the read-modify needs serialising).

---

## 5 - MEDIUM - CONFIRMED - Undo entry manifests are written non-atomically

`src/core/undo.ts:160`

```ts
fs.writeFileSync(entryFile(dataDir, entry.id), JSON.stringify(entry, null, 2), 'utf8')
```

Same defect class as finding 1, smaller blast radius. `parseEntry` swallows malformed JSON and
`listEntries` filters it out (`undo.ts:344-355`), so a truncated manifest is not an error - it is
an **entry that does not exist**. The pre-image blobs survive as orphans until `pruneEntries`
collects them (`undo.ts:441-444`).

The impact is that the safety net silently loses a record: `snapshotFiles` returns the entry id
to the caller, who is told the change is undoable (`undo.ts:183-186`), and `undo_changes` by id
later returns `No undo entry` (`undo.ts:470`).

Two further notes on the same file:
- `restoreEntry` re-snapshots before restoring (`undo.ts:472-479`) and then writes the manifest
  again at `undo.ts:506`. If that second write is lost, the entry stays `open` and `undoLast`
  will offer to undo the same change a second time (`undo.ts:525`).
- `undo.ts:145` uses `crypto.randomBytes(2)` for the id tail - fine for uniqueness, and
  correctly *not* used for anything security-bearing.

**Fix:** tmp + `renameSync`, matching `vault.ts:164-170`.

---

## 6 - MEDIUM - CONFIRMED - The router never skips a route it already knows is down

`src/llm/router.ts:28-41`

```ts
for (const route of routes) {
  try { const res = await route.call(...); ... return res }
  catch (e) { errors.push(...); recordRouteFailure(route.name, msg, route.model); ... }
}
```

Every call walks the full array in fixed order. `recordRouteFailure` correctly classifies the
failure into `ok | degraded | down | unknown` (`routeHealth.ts:25-37`), but **nothing ever reads
that state back for routing decisions** - `getRouteStates()` (`routeHealth.ts:69-71`) is consumed
solely by the UI status tray. I verified this across the repo: the only production reader is the
`/api/health` response (`ui/web/server.ts`, mirrored in the bundle at `blackrose.mjs:13460`), and
`registerRoute`/`routeEntriesFromClient` are display-side too.

So a route whose host is unreachable, or whose key is rejected, costs a **full connect + timeout
on every single turn, forever**, with the error swallowed by the fallback that follows. On a chain
where route 1 is down, that is a per-turn latency tax added to every request the user makes.

This is the mirror image of the key-level logic, which *does* filter correctly
(`router.ts:98` -> `keyUsable`). The route level was built with the same intent and never wired up.

**Fix:** skip routes whose recorded state is `down` within a cooldown, falling back to trying them
all if every route is filtered out - the same pattern `router.ts:99` already uses for keys.

---

## 7 - MEDIUM - CONFIRMED - Embedding key pool does not rotate on transient failures

`src/memory/embedder.ts:218-227` and `343-346`

```ts
function nextKey(cursor) {
  for (let step = 0; step < keys.length; step++) {
    const i = (cursor + step) % keys.length
    if (step === keys.length - 1 || keyUsable(embedKeyId(i))) return { key: keys[i], id, index: i }
  }
}
...
for (let step = 0; step < total; step++) {
  const entry = nextKey(cursor)
  if (!entry) break
  cursor = entry.index          // <-- next iteration starts AT the same index
  for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) { ... }
}
```

`nextKey(cursor)` begins its scan **at** `cursor`. On a transient failure
(`attemptWithKey` returns `{kind:'transient'}` for network errors, aborts, and 5xx -
`embedder.ts:310-330`) **no health record is written**: `recordKeyFailure` is only called for
`rejected` and `spent` (`embedder.ts:367,373`). The key therefore remains `keyUsable`, and the
next outer iteration's `nextKey(cursor)` returns **the same key**.

Net effect: the "one pass over the pool" comment at `embedder.ts:341-342` does not hold for the
most common failure mode. A per-minute 429 or a 5xx (the exact conditions the ladder exists for)
replays the full backoff ladder `pool().length` times on key[0] - 13 keys means up to 65 attempts
and ~6 minutes of dead time on a single credential, while twelve healthy keys sit idle. That is
precisely the waste `configureEmbedKeys` (`embedder.ts:192-199`) was added to eliminate.

**Fix:** advance the cursor past the attempted key (`cursor = entry.index + 1`), or record a
transient failure so `keyUsable` becomes false before the next `nextKey` call.

---

## 8 - MEDIUM - CONFIRMED - `anthropicClient` drops the AbortSignal

`src/llm/client.ts:66`

```ts
async call(system, messages, tools) {          // note: no 4th parameter
  const res = await fetch(`${base}/v1/messages`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-api-key': opts.apiKey, ... },
    body: JSON.stringify({ ... }),
  })                                             // no `signal`
```

`LlmClient.call` accepts `opts?: { signal?: AbortSignal }` (`client.ts:21-26`), and every other
adapter honours it - `openai.ts:210`, `gemini.ts:192,200` (including the explicit pre-flight
aborted check), `onemin.ts:146-150` (with a careful caller-abort bridge). `anthropicClient` is the
sole exception: it does not even declare the parameter, so the signal is unreachable.

Consequence: on the `anthropic` provider, pressing Stop cannot cancel an in-flight request. The
turn runs to completion and the tokens are spent - the exact outcome `client.ts:17-20` says the
signal exists to prevent. The Gemini adapter's comment (`gemini.ts:187-190`) documents this as a
bug that was already found and fixed there; it is still live here.

**Fix:** accept `callOpts` and pass `signal: callOpts?.signal`, plus the
`if (callOpts?.signal?.aborted) throw new Error('aborted')` short-circuit.

---

## 9 - LOW - CONFIRMED - Anthropic keys are mislabelled `openai_key`

`src/memory/redact.ts:37` runs before `:39`:

```ts
{ name: 'openai_key',    re: /\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b/g },   // line 37
{ name: 'anthropic_key', re: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/g },          // line 39
```

`-` is inside the first pattern's character class and `{20,}` is satisfied by `ant-api03-...`,
so an Anthropic key `sk-ant-api03-XYZ...` matches the **openai** pattern first. The secret is
still removed (the replacement is `sk-[REDACTED:openai_key]`, `redact.ts:112`), so this is **not
a leak** - but every user-facing report names the wrong credential kind:
`describeRedactions` (`redact.ts:121-124`) tells the user an *OpenAI* key was found in a document
containing only Anthropic keys.

**Fix:** move `anthropic_key` above `openai_key` (the array docstring at `redact.ts:29` already
says "more specific shapes first" - the order does not honour it).

---

## 10 - LOW - CONFIRMED - Unbounded MCP stdout buffer

`src/mcp/client.ts:45-63`

```ts
this.child.stdout?.on('data', (d: Buffer) => {
  this.buffer += d.toString()
  let idx
  while ((idx = this.buffer.indexOf('\n')) >= 0) { ...slice... }
})
```

`this.buffer` is only ever trimmed when a newline is found. A server that emits a large payload
with no newline (or a long-running line) grows the string without limit, and since `JSON.parse`
is attempted per line, the partial line is retained indefinitely. There is no `maxBuffer`
equivalent here, unlike `core/vault.ts:85` which does set one on its subprocess.

Otherwise the MCP client is sound: `spawn` is called **without** `shell: true` (`client.ts:44`),
so `command`/`args` from `mcp.json` are not shell-interpreted; `loadMcpConfig` requires both
`name` and `command` (`client.ts:28`); and `trusted` defaults to falsy, which makes
`requiresApproval` a gate on every call (`client.ts:142-144`) - fail-closed, as documented.

**Fix:** cap the buffer and drop the connection past the cap.

---

## 11 - LOW - SUSPECTED - Spread on a large array in the retrieval hot path

`src/memory/hybrid.ts:76`

```ts
const maxT = Math.max(...tfidf.map((r) => r.score), 1e-9)
```

`tfidf` is produced by `rankDocs(query, docs, docs.length)` (`hybrid.ts:59`), i.e. it holds an
entry per document in the corpus. `Math.max(...)` spreads into function arguments, and engines cap
the argument count (V8 throws `RangeError: Maximum call stack size exceeded` somewhere in the
1e4-1e5 range, depending on stack depth).

I could not reach this with the shipped corpus, so it is **SUSPECTED, not confirmed** - it needs
a knowledge base several orders of magnitude larger than the 643 chunks referenced in
`hybrid.ts:41`. The fix is trivial and costs nothing: a `reduce`.

---

## Categories that are clean

Reporting these explicitly, since they were in scope:

**Secret leakage - CLEAN.** No API key appears in a URL, query string, log line, or error message
anywhere in scope. Keys travel in headers only, and each adapter says so in its own comments:
`gemini.ts:25` (`x-goog-api-key`, explicitly "keeps the key out of URLs/logs"), `openai.ts:203`
(`authorization` header, conditionally omitted for keyless gateways so no placeholder token is
sent), `client.ts:71` (`x-api-key`), `onemin.ts:155` (`API-KEY`), `embedder.ts:299-304` (whose
comment notes it was "the last place still leaking the secret"), `keys.ts:365` (`authorization`).
Secrets surfaced to the UI pass through `maskSecret` (`keys.ts:88-93`) and the health snapshots
carry only masked ids (`keyHealth.ts:35-37`, `router.ts:112`). `learn_url` validates the scheme
is http(s) (`knowledge.ts:560`).

**Crypto - CLEAN.** `vault.ts:244-272` is a correct AES-256-GCM envelope: a fresh
`crypto.randomBytes(12)` IV per seal (`:246`), the auth tag written into the file (`:249`) and
verified on read with `setAuthTag` so tampering fails closed (`:261`). The master key is 32
bytes from `crypto.randomBytes` (`:222`) and length-checked on load (`:208`). No ECB, no hardcoded
key, no reused nonce, no unauthenticated encryption. The PowerShell interpolation at
`vault.ts:95,101,110` only ever embeds base64 and a module constant, so there is no
shell-injection surface. The `keyfile` fallback (`vault.ts:229`) is plaintext-hex but is
honestly reported as `protection: "keyfile"` (`vault.ts:44,304`) rather than claimed as DPAPI -
and the module docstring states the residual risk plainly (`vault.ts:29-33`). `writePrivate`
(`vault.ts:164-170`) is correctly atomic, and hardening the temp file *before* the rename means
the destination inherits the hardened ACL.

**Path traversal on archive extraction - CLEAN.** `readZip` (`zip.ts:39-74`) is a read-only
visitor that hands `(name, buffer)` to a callback and never constructs a filesystem path from
`name`. The four consumers only compare or regex the name (`docx.ts:18`, `xlsx.ts:38,45`,
`pptx.ts:15`, `epub.ts:33-34`). `epub.ts:37` reduces it to `name.split('/').pop()` purely for a
display heading.

**Regex catastrophic backtracking - CLEAN.** Every hot regex uses lazy quantifiers with a
non-ambiguous tail and no nested unbounded repetition: `docx.ts:23`, `pptx.ts:23`,
`xlsx.ts:20,22,40,52,56`, `redact.ts:37-81`, `pdf.ts:106,114,116`, `epub.ts:15-19`. The one
alternation worth a second look - `xlsx.ts:56`, which has two branches each with `([\s\S]*?)` -
is anchored on a literal `<c` at both branch starts, so a malformed sheet degrades to linear
scanning rather than exponential backtracking. The `gcp_private_key` pattern (`redact.ts:61`)
spans `[\s\S]*?` across a document but is lazy with a literal terminator.

**Undo journal path safety - CLEAN.** `restoreEntry` resolves every target and refuses anything
under the journal directory (`undo.ts:484-488`), and blob ids are shape-checked against `HEX64`
before use (`undo.ts:495`) - both of which close the obvious "restore rewrites its own journal"
and "blob id is attacker-controlled" holes.

**Vault PowerShell surface - CLEAN.** `runPs` (`vault.ts:77-89`) uses `execFileSync` with an
argument array (no shell string interpolation of caller input), `-NoProfile -NonInteractive`, a
10s timeout and a 2 MB `maxBuffer`. `dpapiProtect`/`dpapiUnprotect` (`:98-114`) interpolate only
base64 and the constant `DPAPI_ENTROPY`.

---

## Suggested remediation order

1. `vectors.ts:198` and `undo.ts:160` - adopt the `writePrivate` tmp+rename pattern. Two-line
   changes, removes findings 1 and 5.
2. `zip.ts:65` / `pdf.ts:18,24` - add `maxOutputLength` to both inflate calls.
3. `keyHealth.ts:49` - fix the `[13]` class so 413 stops parking keys.
4. `keystore.ts:118` - serialise the read-modify-write with a lock.
5. `router.ts:28` - consult route state to skip known-down routes.
6. `client.ts:66` - plumb the abort signal into `anthropicClient`.
7. `embedder.ts:346`, `redact.ts:37-39`, `mcp/client.ts:47`, `hybrid.ts:76` - the low-severity set.
