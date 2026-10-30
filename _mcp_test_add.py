"""Regression test: a self-exited MCP child stops being advertised (liveConns hygiene)."""
import sys

P = r'C:\Users\pc\Desktop\BlackRose\cline\blackrose\src\mcp\client.test.ts'
c = open(P, 'rb').read().decode('utf-8')

OLD_IMP = "import { mcpToolsForServer } from './client.ts'"
NEW_I = "import { mcpToolsForServer, registryFor } from './client.ts'"
n = c.count(OLD_IMP)
if n == 1:
    c = c.replace(OLD_IMP, NEW_I)
    print('ok import')
else:
    # already converted by a previous partial run?
    assert NEW_I in c, 'import neither old nor new'
    print('ok import (already applied)')

ANCHOR = "test('mcp: a normal server returns tools (sanity guard for the tests above)', async () => {"
n = c.count(ANCHOR)
assert n == 1, f'anchor: {n}'

if 'a self-exited child stops being advertised' in c:
    print('TEST ALREADY PRESENT')
    sys.exit(0)

TEST = (
    "// ---------------------------------------------------------------------------\r\n"
    "// 2026-10-26 liveConns hygiene (release follow-up): a child that dies on its\r\n"
    "// own must stop being advertised as connected. Against the pre-fix code all\r\n"
    "// three assertions below fail: isConnected stayed true, listServers painted\r\n"
    "// connected:true + toolCount:1 for a corpse, and only call-time threw.\r\n"
    "// ---------------------------------------------------------------------------\r\n"
    "test('mcp: a self-exited child stops being advertised as connected', async () => {\r\n"
    "  const script = writeScript(`\r\n"
    "    import readline from 'node:readline'\r\n"
    "    const send = (m) => process.stdout.write(JSON.stringify(m) + '\\\\n')\r\n"
    "    const rl = readline.createInterface({ input: process.stdin })\r\n"
    "    rl.on('line', (line) => {\r\n"
    "      let msg\r\n"
    "      try { msg = JSON.parse(line) } catch { return }\r\n"
    "      if (msg.method === 'initialize') send({ jsonrpc: '2.0', id: msg.id, result: { protocolVersion: '2024-11-05', capabilities: { tools: {} }, serverInfo: { name: 't', version: '1' } } })\r\n"
    "      else if (msg.method === 'tools/list') send({ jsonrpc: '2.0', id: msg.id, result: { tools: [{ name: 'echo', description: 'e', inputSchema: { type: 'object' } }] } })\r\n"
    "    })\r\n"
    "    // Self-exit shortly after the handshake: the death nobody calls for.\r\n"
    "    setTimeout(() => process.exit(0), 150)\r\n"
    "  `)\r\n"
    "  try {\r\n"
    "    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'br-mcp-hygiene-'))\r\n"
    "    const reg = registryFor(dir, process.cwd())\r\n"
    "    const names = await reg.connect('doomed', { name: 'doomed', command: process.execPath, args: [script], trusted: false })\r\n"
    "    assert.ok(names.some((n) => n === 'mcp__doomed__echo'))\r\n"
    "    assert.equal(reg.isConnected('doomed'), true, 'starts connected')\r\n"
    "    // Poll until the child has exited (deadline 3s), then the roster must\r\n"
    "    // be honest.\r\n"
    "    const deadline = Date.now() + 3000\r\n"
    "    while (reg.isConnected('doomed') && Date.now() < deadline) {\r\n"
    "      await new Promise((r) => setTimeout(r, 50))\r\n"
    "    }\r\n"
    "    assert.equal(reg.isConnected('doomed'), false, 'a self-exited child must not stay connected')\r\n"
    "    assert.equal(reg.listServers().find((s) => s.name === 'doomed')?.connected, false,\r\n"
    "      'listServers must not paint a corpse as connected')\r\n"
    "    assert.throws(() => reg.listTools('doomed'), /not connected/, 'listTools fails closed on a reaped entry')\r\n"
    "  } finally {\r\n"
    "    fs.rmSync(script, { force: true })\r\n"
    "  }\r\n"
    "})\r\n"
    "\r\n"
)

c = c.replace(ANCHOR, TEST + ANCHOR, 1)
open(P, 'wb').write(c.encode('utf-8'))
print('TEST APPLIED')
