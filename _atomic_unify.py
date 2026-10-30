"""Release follow-up: unify the hand-rolled atomic writers onto core/atomicFile.ts.

14 sites / 12 files gain fsync + cleanup-on-failure. Deliberately NOT unified:
  - memory/graph.ts: two halves are flushed BEFORE either rename (deliberate
    cross-file ordering); per-half helper calls would weaken it.
  - core/vault.ts writePrivate: hardenAtRest(tmp) before the rename and
    hardenAtRest(target) after (ACL window); no pre-rename hook in the helper,
    and this is the keystore's only write path.
"""
import sys

ROOT = r'C:\Users\pc\Desktop\BlackRose\cline\blackrose'
IMPORT_CORE = "import { writeFileAtomicAtSync, writeFileAtomicSync } from './atomicFile.ts'"
IMPORT_OUT = "import { writeFileAtomicAtSync, writeFileAtomicSync } from '../core/atomicFile.ts'"

JOBS = []


def job(path, imp, reps):
    JOBS.append((path, imp, reps))


job(r'src\core\budget.ts', IMPORT_CORE, [(
    "  const tmp = `${p}.tmp-${process.pid}-${Date.now()}`\n"
    "  fs.writeFileSync(tmp, JSON.stringify(file, null, 1), 'utf8')\n"
    "  fs.renameSync(tmp, p) // atomic on the same volume: no half-written ledger\n",
    "  // Atomic (tmp + fsync + rename) via the shared helper: no half-written ledger.\n"
    "  writeFileAtomicSync(p, JSON.stringify(file, null, 1))\n",
    'budget writeLedger')])

job(r'src\core\costmeter.ts', IMPORT_CORE, [(
    "  const tmp = p + '.tmp-' + Date.now()\n"
    "  fs.writeFileSync(tmp, JSON.stringify(file, null, 2), 'utf8')\n"
    "  fs.renameSync(tmp, p)\n",
    "  writeFileAtomicAtSync(p, JSON.stringify(file, null, 2))\n",
    'costmeter writeUsage')])

job(r'src\core\policy.ts', IMPORT_CORE, [(
    "  const tmp = `${target}.tmp-${process.pid}`\n"
    "  fs.writeFileSync(tmp, JSON.stringify(policies, null, 2) + '\\n', 'utf8')\n"
    "  fs.renameSync(tmp, target)\n",
    "  writeFileAtomicAtSync(target, JSON.stringify(policies, null, 2) + '\\n')\n",
    'policy savePolicies')])

job(r'src\core\workflow.ts', IMPORT_CORE, [(
    "    const tmp = `${file(dataDir)}.tmp-${process.pid}`\n"
    "    fs.writeFileSync(tmp, JSON.stringify({ version: 1, workflows: defs }, null, 2), 'utf8')\n"
    "    fs.renameSync(tmp, file(dataDir))\n",
    "    writeFileAtomicAtSync(file(dataDir), JSON.stringify({ version: 1, workflows: defs }, null, 2))\n",
    'workflow save')])

job(r'src\core\instanceLock.ts', IMPORT_CORE, [(
    "  const tmp = `${p}.tmp-${process.pid}`\n"
    "  fs.writeFileSync(tmp, JSON.stringify(owner), 'utf8')\n"
    "  fs.renameSync(tmp, p)\n",
    "  writeFileAtomicSync(p, JSON.stringify(owner))\n",
    'instanceLock writeOwner')])

job(r'src\core\plugins.ts', IMPORT_CORE, [(
    "  const tmp = registryFile(dataDir) + '.tmp'\n"
    "  fs.writeFileSync(tmp, JSON.stringify({ version: 1, plugins }, null, 2), 'utf8')\n"
    "  fs.renameSync(tmp, registryFile(dataDir))\n",
    "  writeFileAtomicSync(registryFile(dataDir), JSON.stringify({ version: 1, plugins }, null, 2))\n",
    'plugins writeRegistry')])

job(r'src\tools\custom.ts', IMPORT_OUT, [(
    "  const tmp = file(dataDir) + '.tmp'\n"
    "  fs.writeFileSync(tmp, JSON.stringify({ version: 1, tools: defs }, null, 2), 'utf8')\n"
    "  fs.renameSync(tmp, file(dataDir))\n",
    "  writeFileAtomicSync(file(dataDir), JSON.stringify({ version: 1, tools: defs }, null, 2))\n",
    'custom writeDefs')])

job(r'src\tools\selfimprove.ts', IMPORT_OUT, [(
    "  const tmp = file(dataDir) + '.tmp'\n"
    "  fs.writeFileSync(tmp, JSON.stringify({ version: 1, changes }, null, 2), 'utf8')\n"
    "  fs.renameSync(tmp, file(dataDir))\n",
    "  writeFileAtomicSync(file(dataDir), JSON.stringify({ version: 1, changes }, null, 2))\n",
    'selfimprove saveLedger')])

job(r'src\mcp\client.ts', IMPORT_OUT, [(
    "  const tmp = mcpFile(dataDir) + '.tmp'\n"
    "  fs.writeFileSync(tmp, JSON.stringify({ servers: next }, null, 2), 'utf8')\n"
    "  fs.renameSync(tmp, mcpFile(dataDir))\n"
    "}\n"
    "\n"
    "/** Remove a server's config from <dataDir>/mcp.json by name. */",
    "  writeFileAtomicSync(mcpFile(dataDir), JSON.stringify({ servers: next }, null, 2))\n"
    "}\n"
    "\n"
    "/** Remove a server's config from <dataDir>/mcp.json by name. */",
    'mcp saveMcpServer'),
    (
    "  const tmp = mcpFile(dataDir) + '.tmp'\n"
    "  fs.writeFileSync(tmp, JSON.stringify({ servers: next }, null, 2), 'utf8')\n"
    "  fs.renameSync(tmp, mcpFile(dataDir))\n"
    "  return true",
    "  writeFileAtomicSync(mcpFile(dataDir), JSON.stringify({ servers: next }, null, 2))\n"
    "  return true",
    'mcp removeMcpServer')])

job(r'src\memory\vectors.ts', IMPORT_OUT, [(
    "/** Monotonic suffix so two saves in one process never collide on a temp file. */\n"
    "let tmpCounter = 0\n"
    "\n",
    "",
    'vectors counter'), (
    "  // ATOMIC. This is the whole retrieval index: a plain writeFileSync truncates\n"
    "  // first, so an interrupt (crash, kill, power loss) mid-write leaves a\n"
    "  // half-serialised JSON file and the ENTIRE index is lost with no error — the\n"
    "  // silent data-loss failure mode. Write a sibling temp file, flush it, then\n"
    "  // rename, which is atomic within a filesystem. Same pattern as vault.ts:165.\n"
    "  // Unique per write via pid + a monotonic counter, so two concurrent saves can\n"
    "  // never share a temp file. Avoids importing crypto for one call.\n"
    "  const tmp = `${store.path}.tmp-${process.pid}-${tmpCounter++}`\n"
    "  try {\n"
    "    const fd = fs.openSync(tmp, 'w')\n"
    "    try {\n"
    "      fs.writeFileSync(fd, JSON.stringify(store.file))\n"
    "      fs.fsyncSync(fd)\n"
    "    } finally {\n"
    "      fs.closeSync(fd)\n"
    "    }\n"
    "    fs.renameSync(tmp, store.path)\n"
    "  } catch (e) {\n"
    "    // Leave the previous good index intact rather than swapping in a bad one.\n"
    "    try {\n"
    "      fs.rmSync(tmp, { force: true })\n"
    "    } catch { /* nothing further to do */ }\n"
    "    throw e\n"
    "  }\n",
    "  // ATOMIC. This is the whole retrieval index: a plain writeFileSync truncates\n"
    "  // first, so an interrupt mid-write loses the ENTIRE index with no error. The\n"
    "  // shared helper writes a temp, fsyncs, renames, and cleans the temp when the\n"
    "  // rename fails (leaving the previous good index intact).\n"
    "  writeFileAtomicAtSync(store.path, JSON.stringify(store.file))\n",
    'vectors saveStore')])

job(r'src\session\history.ts', IMPORT_OUT, [(
    "/** Temp-name counter: unique per process without importing crypto for one call. */\n"
    "let tmpCounter = 0\n"
    "\n",
    "",
    'history counter'), (
    "  const tmp = `${p}.tmp-${process.pid}-${tmpCounter++}`\n"
    "  try {\n"
    "    const fd = fs.openSync(tmp, 'w')\n"
    "    try {\n"
    "      fs.writeFileSync(fd, JSON.stringify(file, null, 2), 'utf8')\n"
    "      fs.fsyncSync(fd)\n"
    "    } finally {\n"
    "      fs.closeSync(fd)\n"
    "    }\n"
    "    fs.renameSync(tmp, p)\n"
    "  } catch (e) {\n"
    "    try {\n"
    "      fs.rmSync(tmp, { force: true })\n"
    "    } catch {\n"
    "      /* nothing further to do */\n"
    "    }\n"
    "    throw e // the caller asked us to save; failing silently is worse\n"
    "  }\n",
    "  // The caller asked us to save; failing silently is worse, so the helper's\n"
    "  // error propagates after it has cleaned its temp and kept the old file.\n"
    "  writeFileAtomicSync(p, JSON.stringify(file, null, 2))\n",
    'history saveSession')])

job(r'src\tools\schedule.ts', IMPORT_OUT, [(
    "/** Monotonic suffix so two saves in one process never collide on a temp file. */\n"
    "let tmpCounter = 0\n"
    "\n",
    "",
    'schedule counter'), (
    "  const tmp = `${p}.tmp-${process.pid}-${tmpCounter++}`\n"
    "  try {\n"
    "    const fd = fs.openSync(tmp, 'w')\n"
    "    try {\n"
    "      fs.writeFileSync(fd, JSON.stringify(list, null, 2), 'utf8')\n"
    "      fs.fsyncSync(fd)\n"
    "    } finally {\n"
    "      fs.closeSync(fd)\n"
    "    }\n"
    "    fs.renameSync(tmp, p)\n"
    "  } catch (e) {\n"
    "    // Leave the previous file intact rather than swapping in a partial one.\n"
    "    try {\n"
    "      fs.rmSync(tmp, { force: true })\n"
    "    } catch { /* nothing further to do */ }\n"
    "    throw e\n"
    "  }\n",
    "  // Shared helper: tmp + fsync + rename, temp cleaned when the rename fails\n"
    "  // (the previous good file stays intact).\n"
    "  writeFileAtomicSync(p, JSON.stringify(list, null, 2))\n",
    'schedule saveSchedules')])

job(r'src\core\undo.ts', IMPORT_CORE, [(
    "/** Temp-name counter: unique per process, no crypto import needed for one call. */\n"
    "let entryTmpCounter = 0\n"
    "\n",
    "",
    'undo counter'), (
    "  const tmp = `${file}.tmp-${process.pid}-${entryTmpCounter++}`\n"
    "  try {\n"
    "    const fd = fs.openSync(tmp, 'w')\n"
    "    try {\n"
    "      fs.writeFileSync(fd, JSON.stringify(entry, null, 2), 'utf8')\n"
    "      fs.fsyncSync(fd)\n"
    "    } finally {\n"
    "      fs.closeSync(fd)\n"
    "    }\n"
    "    fs.renameSync(tmp, file)\n"
    "  } catch (e) {\n"
    "    try {\n"
    "      fs.rmSync(tmp, { force: true })\n"
    "    } catch {\n"
    "      /* nothing further to do */\n"
    "    }\n"
    "    // snapshotFiles() catches this, but restoreEntry() does not: an entry that\n"
    "    // cannot be re-written as `restored` must not read as a failed rollback.\n"
    "    throw e\n"
    "  }\n",
    "  // snapshotFiles() catches this failure, but restoreEntry() does not: an entry\n"
    "  // that cannot be re-written as `restored` must not read as a failed rollback.\n"
    "  writeFileAtomicSync(file, JSON.stringify(entry, null, 2))\n",
    'undo writeEntry')])

# --- knowledge.ts: delete the local duplicate, use the shared helper ----------
job(r'src\tools\knowledge.ts', IMPORT_OUT, [(
    "/**\n"
    " * Atomic write (tmp + fsync + rename) - the repo's M5 standard (schedule.ts\n"
    " * saveSchedules). Knowledge readers SKIP unparseable files, so a crash mid\n"
    " * write of a plain writeFileSync silently deleted a whole learned document\n"
    " * from list + search + forget (2026-10-26 sweep M).\n"
    " */\n"
    "function atomicWriteFileSync(p: string, data: string): void {\n"
    "  const tmp = `${p}.tmp-${process.pid}-${Date.now()}`\n"
    "  const fd = fs.openSync(tmp, 'w')\n"
    "  try {\n"
    "    fs.writeSync(fd, data)\n"
    "    fs.fsyncSync(fd)\n"
    "  } finally {\n"
    "    fs.closeSync(fd)\n"
    "  }\n"
    "  fs.renameSync(tmp, p)\n"
    "}\n"
    "\n",
    "",
    'knowledge local helper removed')])

for path, imp, reps in JOBS:
    p = ROOT + '\\' + path
    c = open(p, 'rb').read().decode('utf-8').replace('\r\n', '\n')
    for old, new, label in reps:
        n = c.count(old)
        if n != 1:
            print(f'FAIL {path} :: {label}: found {n}')
            sys.exit(1)
        c = c.replace(old, new)
        print(f'ok {path} :: {label}')
    if path.endswith('knowledge.ts'):
        # rename the 5 call sites of the deleted local helper
        n = c.count('atomicWriteFileSync(')
        assert n == 5, f'knowledge call sites: {n}'
        c = c.replace('atomicWriteFileSync(', 'writeFileAtomicAtSync(')
        print('ok knowledge 5 call sites')
    lines = c.split('\n')
    idx = max(i for i, l in enumerate(lines) if l.startswith('import '))
    lines.insert(idx + 1, imp)
    c = '\n'.join(lines)
    open(p, 'wb').write(c.replace('\n', '\r\n').encode('utf-8'))
print('ALL JOBS APPLIED')
