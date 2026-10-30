"""Helper hardening found by the new concurrency test: temp names need a
monotonic suffix, not just pid+Date.now (two async writes to one target in the
same millisecond collided and the second rename failed ENOENT)."""
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
    "export function writeFileAtomicSync(target: string, data: string): void {\n"
    "  const tmp = `${target}.tmp-${process.pid}-${Date.now()}`\n",
    "/**\n"
    " * Monotonic suffix so two writes in one process can never share a temp name.\n"
    " * pid+Date.now alone is not enough: two concurrent ASYNC writes to the same\n"
    " * target inside one millisecond collided, and the loser's rename failed ENOENT\n"
    " * because the winner had already renamed that temp away. The concurrency test\n"
    " * in atomicFile.test.ts pins this.\n"
    " */\n"
    "let tmpSeq = 0\n"
    "\n"
    "export function writeFileAtomicSync(target: string, data: string): void {\n"
    "  const tmp = `${target}.tmp-${process.pid}-${Date.now()}-${tmpSeq++}`\n",
    'sync temp name')

rep(
    "export async function writeFileAtomic(target: string, data: string): Promise<void> {\n"
    "  const tmp = `${target}.tmp-${process.pid}-${Date.now()}`\n",
    "export async function writeFileAtomic(target: string, data: string): Promise<void> {\n"
    "  const tmp = `${target}.tmp-${process.pid}-${Date.now()}-${tmpSeq++}`\n",
    'async temp name')

open(p, 'wb').write(c.replace('\n', '\r\n').encode('utf-8'))
print('HELPER HARDENED')
