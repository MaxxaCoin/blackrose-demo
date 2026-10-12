// Quick check: the served UI page's inline script must PARSE.
//
// The page lives in src/ui/web/assets.ts as a TypeScript TEMPLATE LITERAL, so a
// single stray real newline (or an unterminated fragment) silently emits broken
// JavaScript — the whole web UI then dies with no server error. This is the
// exact trap that broke the page on 2026-09-27 when the drop-zone block was
// edited twice and a stale copy was left behind.
//
// Run: node validation/check-ui-parse.mjs
const mod = await import('file:///C:/Users/pc/Desktop/BlackRose/cline/blackrose/src/ui/web/assets.ts')
const html = mod.uiHtml()
const start = html.indexOf('<script>') + 8
const end = html.indexOf('</scr' + 'ipt>')
const js = html.slice(start, end)
const vm = await import('node:vm')
try {
  new vm.Script(js)
  console.log(`OK — page script parses (${js.length} chars)`)
} catch (e) {
  console.error(`ERR — page script is broken: ${e.message}`)
  const lines = js.split('\n')
  const m = /:(\d+)/.exec(e.stack ?? '')
  if (m) {
    const n = Number(m[1])
    for (let i = Math.max(0, n - 3); i < Math.min(lines.length, n + 2); i++) {
      console.error(`${i + 1}: ${lines[i]}`)
    }
  }
  process.exit(1)
}
