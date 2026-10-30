"""NEXT release follow-up: build-exe subpath specifier guard + latent test-file fix.

1. Convert the 46 latent sites (`import assert from 'node:assert/strict'`)
   to the slash-free form `import { strict as assert } from 'node:assert'`.
2. build-exe.ts: after the bundle is written, scan the emitted lines for
   subpath node: specifiers and fail with the exact specifier named.
"""
import os
import sys

ROOT = r'C:\Users\pc\Desktop\BlackRose\cline\blackrose'
OLD = "import assert from 'node:assert/strict'"
NEW = "import { strict as assert } from 'node:assert'"

changed = 0
skip_parts = ('node_modules', 'dist-build', os.path.join('desktop', 'tauri'))
for sub in (os.path.join(ROOT, 'src'), os.path.join(ROOT, 'scripts')):
    for dirpath, dirnames, filenames in os.walk(sub):
        dirnames[:] = [d for d in dirnames if d not in ('node_modules', 'dist-build', 'node')]
        for fn in filenames:
            if not fn.endswith('.ts'):
                continue
            p = os.path.join(dirpath, fn)
            raw = open(p, 'rb').read()
            c = raw.decode('utf-8')
            n = c.count(OLD)
            if n == 0:
                continue
            c = c.replace(OLD, NEW)
            open(p, 'wb').write(c.encode('utf-8'))
            changed += 1
print(f'assert imports converted: {changed}')
if changed != 46:
    print(f'WARNING: expected 46 sites, got {changed}')

# ---- build-exe.ts guard -----------------------------------------------------
P = os.path.join(ROOT, 'scripts', 'build-exe.ts')
c = open(P, 'rb').read().decode('utf-8')

OLD_B = (
    "fs.writeFileSync(bundlePath, [...headerSet, 'const __mod = {};', ...outLines].join('\\n\\n') + '\\n')\n"
    "console.log(`  bundle        → ${bundlePath} (${mods.size} modules)`)\n"
    "sh(`node --check ${JSON.stringify(bundlePath)}`)\n"
)
NEW_B = (
    "fs.writeFileSync(bundlePath, [...headerSet, 'const __mod = {};', ...outLines].join('\\n\\n') + '\\n')\n"
    "console.log(`  bundle        → ${bundlePath} (${mods.size} modules)`)\n"
    "// Subpath-specifier guard (2026-10-26 release follow-up). The hoist regexes\n"
    "// accept slash-free specifiers only: a `node:x/y` import (node:assert/strict,\n"
    "// node:fs/promises — the class that broke the build live once) survives into\n"
    "// a wrapped module body, where an import declaration is illegal ESM. The\n"
    "// node --check below catches a violation INSIDE the graph, then only as a\n"
    "// bare SyntaxError; this scan reads the emitted bundle and NAMES the\n"
    "// specifier, so the failure message is the fix.\n"
    "const subpathHits: string[] = []\n"
    "for (const line of [...headerSet, ...outLines]) {\n"
    "  const m = /(?:from\\s+|import\\(\\s*|require\\(\\s*)'node:[A-Za-z0-9_]+\\/[^']*'/.exec(line)\n"
    "  if (m) subpathHits.push(line.trim())\n"
    "}\n"
    "if (subpathHits.length > 0) {\n"
    "  console.error(\n"
    "    `  bundle        → FAIL: ${subpathHits.length} subpath node: specifier(s) reached the bundle.\\n` +\n"
    "    '  The bundler hoists slash-free specifiers only (node:dns + dns.promises, not\\n' +\n"
    "    '  node:dns/promises). Rewrite the offending import as a namespace accessor:\\n' +\n"
    "    \"  `import fs from 'node:fs'` + `fs.promises.writeFile(...)` — the knowledge.ts dns pattern.\\n\" +\n"
    "    subpathHits.map((l) => `    ${l.slice(0, 140)}`).join('\\n'),\n"
    "  )\n"
    "  process.exit(1)\n"
    "}\n"
    "sh(`node --check ${JSON.stringify(bundlePath)}`)\n"
)

n = c.count(OLD_B)
if n != 1:
    # try CRLF
    OLD_B = OLD_B.replace('\n', '\r\n')
    NEW_B = NEW_B.replace('\n', '\r\n')
    n = c.count(OLD_B)
    if n != 1:
        print(f'FAIL build-exe anchor: found {n}')
        sys.exit(1)
    c = c.replace(OLD_B, NEW_B)
else:
    c = c.replace(OLD_B, NEW_B)
open(P, 'wb').write(c.encode('utf-8'))
print('build-exe guard applied')
