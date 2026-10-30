"""Harden the helper's rename step for Windows: a concurrent rename (or an
antivirus/indexer holding the target) makes rename fail transiently with
EPERM/EACCES/EBUSY. Retry a few times before giving up; the existing cleanup
path still runs when every attempt fails (e.g. the target is a directory)."""
import sys

p = r'C:\Users\pc\Desktop\BlackRose\cline\blackrose\src\core\atomicFile.ts'
c = open(p, 'rb').read().decode('utf-8').replace('\r\n', '\n')


def rep(old, new, label):
    global c
    n = c.count(old)
    if n != 1:
        print(f'FAIL {label}: found {n}')
        sys.exit(1)
    c = c.replace(old, new)
    print(f'ok {label}')


rep(
    "let tmpSeq = 0\n",
    "let tmpSeq = 0\n"
    "\n"
    "/**\n"
    " * Windows makes rename transiently fail: another writer's rename may hold the\n"
    " * target for a moment, and an antivirus/indexer holding a handle reports the\n"
    " * same EPERM/EACCES/EBUSY. Those are worth a short, bounded retry; anything\n"
    " * else (or a target that is a directory) must throw immediately.\n"
    " */\n"
    "const RETRYABLE_RENAME = new Set(['EPERM', 'EACCES', 'EBUSY'])\n"
    "const RENAME_ATTEMPTS = 5\n"
    "\n"
    "function retryableRename(e: unknown): boolean {\n"
    "  const code = (e as NodeJS.ErrnoException | null)?.code\n"
    "  return typeof code === 'string' && RETRYABLE_RENAME.has(code)\n"
    "}\n"
    "\n"
    "function sleepSync(ms: number): void {\n"
    "  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms)\n"
    "}\n",
    'retry helpers')

rep(
    "  try {\n"
    "    fs.renameSync(tmp, target)\n"
    "  } catch (e) {\n",
    "  try {\n"
    "    for (let attempt = 1; ; attempt++) {\n"
    "      try {\n"
    "        fs.renameSync(tmp, target)\n"
    "        break\n"
    "      } catch (e) {\n"
    "        if (attempt >= RENAME_ATTEMPTS || !retryableRename(e)) throw e\n"
    "        sleepSync(10 * attempt)\n"
    "      }\n"
    "    }\n"
    "  } catch (e) {\n",
    'sync rename retry')

rep(
    "  try {\n"
    "    await fs.promises.rename(tmp, target)\n"
    "  } catch (e) {\n",
    "  try {\n"
    "    for (let attempt = 1; ; attempt++) {\n"
    "      try {\n"
    "        await fs.promises.rename(tmp, target)\n"
    "        break\n"
    "      } catch (e) {\n"
    "        if (attempt >= RENAME_ATTEMPTS || !retryableRename(e)) throw e\n"
    "        await new Promise((r) => setTimeout(r, 10 * attempt))\n"
    "      }\n"
    "    }\n"
    "  } catch (e) {\n",
    'async rename retry')

open(p, 'wb').write(c.replace('\n', '\r\n').encode('utf-8'))
print('RENAME RETRY ADDED')
