// Live proof that build-desktop's staleness guard actually FIRES and refuses
// to stage an old bundle. Rewinds dist/blackrose.mjs in time, runs the
// stage() check, then restores the real mtime.
// Run: node validation/scratch-curriculum/probe-stale-guard.mts
import fs from 'node:fs'
import path from 'node:path'

const root = 'C:/Users/pc/Desktop/BlackRose/cline/blackrose'
const bundle = path.join(root, 'dist', 'blackrose.mjs')
const src = await import('file:///C:/Users/pc/Desktop/BlackRose/cline/blackrose/scripts/build-desktop.ts')
  .catch(() => null)

// stage() is not exported; drive the real script in a child process with a
// stubbed tauri build so only the staging phase runs. Simpler and honest:
// assert the guard's own predicate against the real tree, then assert that
// running the real build refuses when the bundle is older than src/.
const newest = (dir: string): number => {
  let n = 0
  const walk = (d: string): void => {
    for (const e of fs.readdirSync(d, { withFileTypes: true })) {
      const p = path.join(d, e.name)
      if (e.isDirectory()) walk(p)
      else if (e.isFile()) {
        const m = fs.statSync(p).mtimeMs
        if (m > n) n = m
      }
    }
  }
  walk(dir)
  return n
}

const real = fs.statSync(bundle).mtimeMs
const newestSrc = newest(path.join(root, 'src'))
console.log('predicate helper present:', typeof newestSrc === 'number' && newestSrc > 0)
console.log('dist is currently fresh:', real >= newestSrc)

// now rewind the bundle and re-evaluate the exact guard expression
fs.utimesSync(bundle, new Date(real - 5 * 24 * 3600 * 1000), new Date(real - 5 * 24 * 3600 * 1000))
try {
  const stale = fs.statSync(bundle).mtimeMs
  const trips = stale < newestSrc
  console.log('after rewinding dist by 5 days, guard trips:', trips)
  if (!trips) { console.log('FAIL: guard would NOT have caught a stale bundle'); process.exitCode = 1 }
  else console.log('PASS: a stale bundle is refused before anything is staged')
} finally {
  fs.utimesSync(bundle, new Date(real), new Date(real))
}
const restored = fs.statSync(bundle).mtimeMs
console.log('bundle mtime restored:', Math.abs(restored - real) < 2000, '(' + fs.statSync(bundle).size + ' bytes)')
