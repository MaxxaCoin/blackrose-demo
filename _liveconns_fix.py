"""liveConns stale-entry hygiene (release follow-up): a self-exited MCP child
must stop being advertised as connected.

- McpConnection gains onDeath (fires once on the alive->dead transition) and
  isDead(); failAll becomes idempotent (exit + stdin error can both fire).
- mcpToolsForServer / McpRegistry.connect wire an identity-checked reaper that
  removes the registry's OWN entry when ITS connection dies.
- killAll reaps liveConns synchronously; isConnected/listServers also consult
  isDead() so the roster never paints a corpse.
"""
import sys

P = r'C:\Users\pc\Desktop\BlackRose\cline\blackrose\src\mcp\client.ts'
c = open(P, 'rb').read().decode('utf-8').replace('\r\n', '\n')


def rep(old, new, label):
    global c
    n = c.count(old)
    if n != 1:
        print(f'FAIL {label}: found {n}')
        sys.exit(1)
    c = c.replace(old, new)
    print(f'ok {label}')


# 1. connection death hook + honest isDead + idempotent failAll
rep(
    "  private seq = 0\n"
    "  private pending = new Map<number, (r: JsonRpcResponse) => void>()\n"
    "  private dead = false\n",
    "  private seq = 0\n"
    "  private pending = new Map<number, (r: JsonRpcResponse) => void>()\n"
    "  private dead = false\n"
    "\n"
    "  /**\n"
    "   * Called ONCE on the alive→dead transition (child exit / error / stdin\n"
    "   * failure). Registries hook it to reap stale entries — a child that died on\n"
    "   * its own used to keep being advertised as connected (isConnected true,\n"
    "   * listServers `connected:true, toolCount:1` for a corpse). Identity checks\r\n"
    "   * live at the hook sites, so a superseding connection is never touched.\r\n"
    "   */\n"
    "  onDeath: (() => void) | null = null\n"
    "\n"
    "  isDead(): boolean {\n"
    "    return this.dead\n"
    "  }\n",
    'onDeath field')

# 2. failAll idempotent + fires the hook
rep(
    "  private failAll(reason: string): void {\n"
    "    this.dead = true\n"
    "    this.failPending(reason)\n"
    "  }\n",
    "  private failAll(reason: string): void {\n"
    "    // Idempotent: 'exit' and a stdin 'error' can both fire for one death,\n"
    "    // and kill() escalations must not re-run the reaper.\n"
    "    if (this.dead) return\n"
    "    this.dead = true\n"
    "    this.failPending(reason)\n"
    "    try {\n"
    "      this.onDeath?.()\n"
    "    } catch {\n"
    "      /* a reaper must never break the death path */\n"
    "    }\n"
    "  }\n",
    'failAll hook')

# 3. boot/interactive tool path: reap liveConns on death
rep(
    "  const conn = new McpConnection(server, cwd)\n"
    "  let remote: { name: string; description?: string; inputSchema: unknown }[]\n",
    "  const conn = new McpConnection(server, cwd)\n"
    "  // Reap on self-exit (2026-10-26 liveConns hygiene): a child that dies on\n"
    "  // its own must not stay in liveConns — the tool run's `liveConns.get(...) ?? conn`\n"
    "  // fallback would then answer with a dead connection forever. Identity-checked:\n"
    "  // a superseding connection may already own the name.\n"
    "  conn.onDeath = () => {\n"
    "    if (liveConns.get(server.name) === conn) liveConns.delete(server.name)\n"
    "  }\n"
    "  let remote: { name: string; description?: string; inputSchema: unknown }[]\n",
    'tools path reaper')

# 4. interactive registry: reap both this.conns and liveConns on death
rep(
    "    this.conns.set(name, { conn, tools, trusted: server.trusted === true })\n"
    "    liveConns.set(name, conn)\n",
    "    this.conns.set(name, { conn, tools, trusted: server.trusted === true })\n"
    "    liveConns.set(name, conn)\n"
    "    // Same reap for the interactive registry: a corpse must flip isConnected\n"
    "    // and listServers to honest instead of failing only at call time.\n"
    "    conn.onDeath = () => {\n"
    "      if (liveConns.get(name) === conn) liveConns.delete(name)\n"
    "      const cur = this.conns.get(name)\n"
    "      if (cur?.conn === conn) this.conns.delete(name)\n"
    "    }\n",
    'registry connect reaper')

# 5. killAll: clear liveConns entries pointing at the registry's connections
rep(
    "  killAll(): void {\n"
    "    for (const e of this.conns.values()) e.conn.kill()\n"
    "    this.conns.clear()\n"
    "  }\n",
    "  killAll(): void {\n"
    "    for (const [name, e] of this.conns) {\n"
    "      // kill() raises 'exit' asynchronously, so reap HERE as well — a panic\n"
    "      // must leave no dead entry behind (the same-corpse check makes the\n"
    "      // later onDeath callback a no-op).\n"
    "      if (liveConns.get(name) === e.conn) liveConns.delete(name)\n"
    "      e.conn.kill()\n"
    "    }\n"
    "    this.conns.clear()\n"
    "  }\n",
    'killAll reap')

# 6. honest status: isConnected / listServers consult isDead as belt-and-braces
rep(
    "  isConnected(name: string): boolean {\n"
    "    return this.conns.has(name)\n"
    "  }\n",
    "  isConnected(name: string): boolean {\n"
    "    const e = this.conns.get(name)\n"
    "    return !!e && !e.conn.isDead()\n"
    "  }\n",
    'isConnected honest')

rep(
    "        trusted: live ? live.trusted : s.trusted === true,\n"
    "        connected: !!live,\n",
    "        trusted: live ? live.trusted : s.trusted === true,\n"
    "        connected: !!live && !live.conn.isDead(),\n",
    'listServers honest')

open(P, 'wb').write(c.replace('\n', '\r\n').encode('utf-8'))
print('LIVECONNS FIX APPLIED')
