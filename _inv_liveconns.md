# Investigation: `liveConns` stale-entry hygiene (BlackRose `cline/blackrose`, v0.10.2)

Read-only investigation, 2026-10-26. Nothing in `src/` was modified. Evidence probe was a
throwaway script outside the repo tree (temp dir, since deleted).

## 0. Scope & ground truth

The handoff lists the follow-up verbatim: `docs/08-SESSION-HANDOFF.md:45` — "Open follow-ups:
DNS-rebinding residual, build-exe subpath imports, **liveConns stale-entry hygiene**,
`BLACKROSE_MAX_TURNS=\"\"`".

There is exactly one `liveConns` map, plus two sibling registries that share the defect class:

| Registry | Location | Contents |
|---|---|---|
| `liveConns` | `src/mcp/client.ts:274` — `const liveConns = new Map<string, McpConnection>()` | module-private; name → live McpConnection; boot path + interactive registry share it (comment at 268-273) |
| `bootKills` | `src/mcp/client.ts:264` | module-private; server name → boot child kill handle |
| `McpRegistry.conns` | `src/mcp/client.ts:387` (class at 386) | interactive registry entry `{conn, tools, trusted}` |
| `openMcp` (plugins) | `src/core/plugins.ts:303` | plugin id → MCP child kill handle (reuses `mcpToolsForServer`, `plugins.ts:340-342`) |

Doctor / `/api/jobs` / UI do **not** read MCP state (grep over `doctor.ts` and `src/ui/**` found
no `listServers`/`mcp` reference). The only user-visible surfaces are the `mcp_list_servers`
tool (`src/tools/mcp.ts:81-100`) and `McpRegistry.isConnected/listTools/call`.

## 1. How an entry dies vs. how the registries learn about it

`McpConnection` handles child death correctly at the connection level
(`src/mcp/client.ts:101-103`):

```ts
this.child.on('error',  (e) => this.failAll(`... failed to start ...`))
this.child.stdin?.on('error', (e) => this.failAll(`... stdin failed ...`))
this.child.on('exit', (code) => this.failAll(`... exited (code ${code ?? 'null'})`))
```

`failAll` (`client.ts:90-93`) only sets the instance flag `dead = true` (`client.ts:82,91`) and
rejects pending requests. **It notifies nobody.** No code path anywhere deletes from
`liveConns`, `McpRegistry.conns`, `bootKills`, or `openMcp` in response to a child `exit`.
The only prune paths are explicit user/teardown actions:
`McpRegistry.disconnect` (`client.ts:432-441`, deletes at 436-437) and the supersede path in
`connect` (`client.ts:426-427`, overwrite). Everything else goes stale.

## 2. Stale-entry paths (each with symptom)

### S1 — child self-exit leaves registry + liveConns entries behind (the core defect)
- **Path:** `client.ts:103` exit → `failAll` marks the `McpConnection` dead (`client.ts:91`) →
  `liveConns` entry (`client.ts:218` boot, `client.ts:427` interactive) and
  `McpRegistry.conns` entry (`client.ts:426`) survive forever. `bootKills`
  (`client.ts:319-321`) and `openMcp` (`plugins.ts:341`) also keep their handles.
- **Symptom (measured, see §5):** after the child process exits on its own,
  `isConnected()` still returns `true` (`client.ts:444-445` — pure `this.conns.has(name)`),
  `listServers()` still reports `connected:true, toolCount:1` (`client.ts:459-467`,
  `connected: !!live` at 466), `listTools` still advertises the full tool roster
  (`client.ts:472-476`), and only an actual call fails (`client.ts:134` → "MCP connection is
  closed"). A self-exited server looks connected forever; `mcp_disconnect` on it is the only
  way to clear the ghost. `killAll` (`client.ts:504-507`) and `killBootMcpServers`
  (`client.ts:294-301`) iterate stale entries and invoke `kill()` on dead PIDs —
  the roster grows stale and teardown iterates zombies.
- **Evidence tier:** first-hand (code + executed probe, §5).

### S2 — `killAll()` forgets `liveConns`
- **Path:** `client.ts:504-507`: `for (const e of this.conns.values()) e.conn.kill();
  this.conns.clear()` — `liveConns` is never touched, so after `runEmergencyTeardown`
  (`src/tools/emergency.ts:58`) every interactive entry remains in `liveConns` pointing at a
  killed conn. Boot ToolDefs resolve `liveConns.get(name) ?? conn` (`client.ts:243`) and keep
  resolving the dead interactive conn; a later same-name `connect` fixes the map, but between
  emergency teardown and any reconnect the map is a lying roster.
- **Symptom:** after the panic stop, module state still claims those server names are live
  (matters for any future consumer of `liveConns`, and the boot-tool fallback resolves a dead
  conn instead of reporting "gone"); inconsistent with `disconnect()`, which does delete
  (`client.ts:437`).
- **Evidence tier:** first-hand code reading (behavioral probe covers S1; this path is
  internal-only, verified by reading).

### S3 — boot vs interactive divergence
- A boot-loaded child (`registerMcpTools`, `client.ts:311-326`; `liveConns.set` at
  `client.ts:218`) never appears in `McpRegistry.conns`, so `mcp_list_servers`
  (`src/tools/mcp.ts:81-96` → `listServers`, `client.ts:459-467` iterates `fileCfg` only)
  shows a boot-connected, fully live server as `○ not connected`, and `isConnected` is `false`
  for it while its tools answer. Conversely, when a boot child self-exits, nothing tells
  `bootKills`: `killBootServer(name)` keeps returning `true` for a dead child
  (`client.ts:280-292`), and `killBootMcpServers` keeps "killing" it.
- Plugin MCP children are a third, separate roster keyed by plugin id (`plugins.ts:303,341`) —
  invisible to `listServers` by construction; a stale `openMcp` entry there is benign (its only
  consumer is `closeMcp`, `plugins.ts:307-315`, where `kill()` is idempotent — `client.ts:193-205`
  guards pid and catches), but it is the same hygiene pattern.

### S4 — supersede path (handled, for contrast)
`McpRegistry.connect` handshakes the replacement first, kills `prev` and the boot child
(`client.ts:420-425`), then overwrites both maps (`426-427`). Correct — this path is NOT a
stale-entry source; listed so the fix doesn't disturb it. Same for the double-boot guard
(`client.ts:318-321`) and the failed-handshake cleanup (`client.ts:221-225`, `413-418`).

## 3. Minimal fix (fail-closed style, all inside src/mcp/client.ts)

1. **Honest death transition** — in `McpConnection` (`client.ts:82-93`):
   - add a public `onDeath: () => void = () => {}` field and an `isDead()` accessor
     (`return this.dead`);
   - make `failAll` idempotent (`if (this.dead) return`) and fire `this.onDeath()` exactly once
     on the alive→dead transition. (`failPending` at `client.ts:157-160` — the buffer-overflow
     path — stays non-terminal as it is.)
2. **Wire the owners at set-time**:
   - boot path, `mcpToolsForServer` next to `liveConns.set` (`client.ts:218`):
     ```ts
     conn.onDeath = () => { if (liveConns.get(server.name) === conn) liveConns.delete(server.name) }
     ```
   - registry path, `McpRegistry.connect` next to `this.conns.set` (`client.ts:426`):
     ```ts
     conn.onDeath = () => {
       const cur = this.conns.get(name)
       if (cur?.conn === conn) this.conns.delete(name)
       if (liveConns.get(name) === conn) liveConns.delete(name)
     }
     ```
   The identity check (`=== conn`) is load-bearing: a self-exited OLD conn must never evict a
   NEW superseding conn registered under the same name.
3. **`killAll` prunes `liveConns` too** (`client.ts:504-507`):
   ```ts
   killAll(): void {
     for (const [name, e] of this.conns) {
       e.conn.kill()
       if (liveConns.get(name) === e.conn) liveConns.delete(name)
     }
     this.conns.clear()
   }
   ```
4. **Belt-and-braces honest status** (exit events are async; a reader can race the prune):
   `isConnected` (`client.ts:444-445`) → `const e = this.conns.get(name); return !!e && !e.conn.isDead()`;
   `listServers` (`client.ts:466`) → `connected: !!live && !live.conn.isDead`.

This keeps the fail-closed doctrine already in the file (dead conns fail closed in `request`,
`client.ts:134`): the registry now *reports* dead instead of pretending live. The boot ToolDef
fallback at `client.ts:243` (`liveConns.get(...) ?? conn`) needs no change — after pruning it
falls back to the boot conn, which is equally dead, and the run already returns
`isError: true` (`client.ts:245-248`). Optional hardening (not required): `live && !live.isDead`.

## 4. Regression test (evidence it fails on current code)

**File:** `src/mcp/client.test.ts` (same real-stdio style as `src/emergency.test.ts:110-161`,
which drives `mcp/fakeServer.ts`; `src/mcp/client.test.ts:57-80` shows the writeScript +
`mcpToolsForServer` pattern).

**Assertion shape** (new test, self-exiting server = fakeServer + `setTimeout(() =>
process.exit(0), 100)` after answering `tools/list`):

```ts
test('mcp: a server that exits on its own is honestly reported, not listed as connected', async () => {
  // server script: full handshake + tools/list, then process.exit(0)
  const reg = registryFor(dir, dir)
  await reg.connect('selfexit', { name: 'selfexit', command: process.execPath, args: [script] })
  assert.equal(reg.isConnected('selfexit'), true)
  await new Promise((r) => setTimeout(r, 800))          // child exits on its own
  assert.equal(reg.isConnected('selfexit'), false)        // FAILS today: stays true
  assert.equal(reg.listServers().find((s) => s.name === 'selfexit')?.connected, false) // FAILS today: true
  assert.throws(() => reg.listTools('selfexit'), /not connected/)                      // FAILS today: returns roster
})
```

**Measured failure against current code** (executed 2026-10-26, Node v24.20.0, throwaway
probe outside src/, since removed): after the self-exit,
`isConnected = true`; `listServers` = `[{connected:true, toolCount:1}]`; `listTools` returned
`[{"name":"echo",...}]`; `call` rejected "MCP connection is closed". I.e. the test's three
first assertions all fail pre-fix; the call-level failure is the only honest signal today.

A second assertion pins S2: `connect` a persistent server, `reg.killAll()`, then assert a
`mcpToolsForServer`-registered boot tool for the same name and any subsequent
`registryFor(...).connect(name, inline)` behave — plus (white-box, if an `isDead()` accessor is
exported for tests) `liveConns` no longer holds the name after `killAll`.

## 5. Adjacent callers that must change (or be checked)

- `src/tools/mcp.ts:81-96` (`mcp_list_servers`) — no code change; its "● connected" line
  becomes honest automatically via `listServers`.
- `src/tools/emergency.ts:58` (`killAll`) — no change at call site; the fix lives in
  `killAll` itself. `emergency.test.ts:110-161` already pins the kill side.
- `src/core/plugins.ts:303,341` (`openMcp`) — optional: same hygiene could be wired by
  extending `mcpToolsForServer` to accept an `onDeath` owner callback; current staleness is
  benign (`closeMcp` deletes, `kill()` is idempotent), so record-not-fix is defensible.
- Boot ToolDef fallback `client.ts:243` — no change needed; optionally harden to
  `live && !live.isDead` so a raced prune still falls back.

## 6. Confidence

- S1 mechanism + symptom: **determined** (first-hand code + executed probe).
- S2/S3: **high confidence** (first-hand code reading; S2's liveConns staleness is
  module-internal, not externally observable without the fix's accessor).
- openMcp (plugins) being benign: **high confidence** by reading `kill()` (`client.ts:193-205`)
  and `closeMcp` (`plugins.ts:307-315`); no test executed for that path.
