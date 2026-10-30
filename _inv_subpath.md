# Investigation: SEA-bundling "subpath specifier" hazard (node:x/y class)

Repo: `cline/blackrose` @ C:\Users\pc\Desktop\BlackRose — read-only; no src/ or scripts/ files modified.
Date: 2026-10-26. Evidence tier: 一手代码 (bundle source + repo grep) + one non-mutating runtime probe (temp file outside repo).

## 1. The exact rule build-exe.ts enforces

`scripts/build-exe.ts` transforms each tsc-emitted module in `transform()`:

- **build-exe.ts:95** — hoist regex for default/named imports:
  `/^import\s*(.+?)\s*from\s+'((?:node:)?[A-Za-z_][\w]*)'\s*;?$/gm`
- **build-exe.ts:100** — side-effect import hoist regex: `/^import\s+'((?:node:)?[A-Za-z_][\w]*)'\s*;?$/gm`
- **build-exe.ts:85–92** — `NODE_BUILTIN` set + `norm()`: bare specifiers normalized to `node:…`.
- Strip regexes (95/100 match, then removal at 103–105; relative strip at 119/125 uses `[\w./-]+` which cannot match a `:`).

**Rule (de facto):** every static import specifier must be slash-free — either `node:x` or a bare builtin (`fs`, `path`…). Any `node:x/y` (e.g. `node:assert/strict`, `node:fs/promises`) matches **neither** the hoist regexes nor the strip regexes (the relative-import strip `[\w./-]+` excludes `:`), so the statement is left verbatim inside the wrapped module body `function M…() { … return {} }` (built at build-exe.ts:169–172). An `import` declaration inside a function body is illegal ESM → the internal gate `sh(`node --check ${bundlePath}`)` at **build-exe.ts:206** throws and the build dies. There is **no CLI flag parsing** in build-exe.ts (no `process.argv` anywhere), so there is **no non-mutating `--check` mode**; the gate only runs as part of the mutating build (which rmSync's dist-build/ and writes dist/ — hence not run here).

## 2. Every remaining subpath-specifier occurrence (src/ + scripts/)

Full scan (`rg "node:[a-z]+/" src scripts`): **46 occurrences, all `node:assert/strict`; zero occurrences of `node:fs/promises`, `node:stream/promises`, `node:timers/promises`, `node:dns/promises` or any other `node:x/y`.** Zero occurrences in bundle-reachable non-test code.

| Occurrence | Count | In bundle graph? | Status | Evidence |
|---|---|---|---|---|
| `src/**/*.test.ts` → `import assert from 'node:assert/strict'` | 45 files (1 hit each) | **No** | **latent only** | entry is `load('index.js')` (build-exe.ts:165); `src/index.ts` imports no `.test` file (`rg "\.test\.js|\.test'" src --glob '!*.test.ts'` → 0 hits); tests run directly via `node --test` on TS (package.json `test` script). tsc emits them to dist-build/ but `emit()` never loads them. |
| `scripts/mcpv/verify.ts:4` — same specifier | 1 | **No** | **latent only** | build-exe.ts step 1 uses `--rootDir src` (build-exe.ts:35), so scripts/ is never emitted into buildDir; unreachable from index.js. |

**Breaking today: zero.** All 46 sites are latent: they would hard-fail the build (via the build-exe.ts:206 `node --check` gate, per §4 probe) only if such a file entered the graph — e.g. a future `import … from '../some.test.js'` or moving a helper out of a test file.

Dynamic imports checked: `await import('node:sea')` (src/index.ts:132), `await import('node:child_process')` (src/ui/web/main.ts:220), `await import('node:vm')` (src/smoke.ts:2509) — all slash-free; and dynamic `import()` inside a function body is legal ESM, so the bundler mishandles nothing there (transform leaves the line in the module body untouched). No `require('node:x/y')` anywhere.

## 3. Precise minimal fix per site

Pattern (already the repo precedent for the same class of bug):

- **Precedent (dns/promises fix):** `src/tools/knowledge.ts:2` — `import dns from 'node:dns'` … `src/tools/knowledge.ts:337` — `await dns.promises.lookup(host, { all: true, verbatim: true })` (slash-free specifier + `.promises` namespace accessor).

For the 46 `node:assert/strict` sites the one-line equivalent is:

```ts
import { strict as assert } from 'node:assert'   // slash-free; named export `strict` (= assert.strict)
```

Same object, same API (`assert.equal` etc. under `strict` semantics); no body changes. Alternative equivalent: `import assert from 'node:assert'` + `const run = assert.strict` — but the named-import form is strictly one line and matches the hoister's regex. For a hypothetical future `node:fs/promises` user, the repo pattern is: `import fs from 'node:fs'` + call sites `fs.promises.writeFile(...)` (i.e. the knowledge.ts dns pattern).

## 4. Gate / regression check + evidence it fails today

Existing gate: `node --check` (build-exe.ts:206) followed by runtime `--doctor` (build-exe.ts:209). Evidence it catches this class (non-mutating probe, %TEMP% file shaped exactly like the emitted bundle — module body wrapped in `function M…()`):

```
function M1() {
import assert from 'node:assert/strict';
return { assert };
}
→ node --check: SyntaxError: Unexpected identifier 'assert' (exit 1), Node v24.20.0
```

So a subpath specifier that ever reaches the bundle graph fails loudly at step 2, never reaching SEA. What the gate does **not** catch today: violations in files outside the graph (all 46 current sites) — the build passes silently regardless.

**Recommended guard** (to be added to build-exe.ts, not done here): after tsc emit, before bundling, scan dist-build and fail if `/^import\s.*from\s+'node:[^']+\//m` or `/\bimport\(\s*'node:[^']+\//` matches, printing file:line. Simulate non-mutatingly: the same regex over src/+scripts/ today returns 46 hits → the guard would fail on the current tree only if tests/scripts were in scope; scoping it to the bundle graph (`mods.keys()`) makes it exact. A cheaper complement: a `node --test`-style assertion in scripts that greps the emitted bundle for `/^import .*node:[\w]+\/` at line-start inside function bodies — but the scan-at-emit-step is the precise, minimal fix.

## 待证项
- None blocking. (Handoff's `--check` mode for build-exe.ts does not exist; verified by reading the whole script — no argv handling.)
