"""NEXT WORK item 9 (bridge client): bounded calls instead of an unbounded fetch."""
import sys

P = r'src\bridge\client.ts'
c = open(P, 'rb').read().decode('utf-8')


def rep(old, new, label):
    global c
    n = c.count(old)
    if n != 1:
        print(f'FAIL {label}: found {n}')
        sys.exit(1)
    c = c.replace(old, new)
    print(f'ok {label}')


rep(
    "async function jsonCall<T>(\r\n"
    "  base: string,\r\n"
    "  token: string,\r\n"
    "  route: string,\r\n"
    "  body?: unknown,\r\n"
    "  method = 'POST',\r\n"
    "): Promise<T> {\r\n"
    "  const res = await fetch(base.replace(/\\/$/, '') + route, {\r\n"
    "    method,\r\n"
    "    headers: {\r\n"
    "      'content-type': 'application/json',",
    "async function jsonCall<T>(\r\n"
    "  base: string,\r\n"
    "  token: string,\r\n"
    "  route: string,\r\n"
    "  body?: unknown,\r\n"
    "  method = 'POST',\r\n"
    "): Promise<T> {\r\n"
    "  // Bounded (2026-10-26, NEXT WORK item 9): a bridge host that accepted the\r\n"
    "  // connection and then hung used to wedge the caller forever. /ask and /goal\r\n"
    "  // legitimately run a full agent turn, so the ceiling is generous (10 min)\r\n"
    "  // and env-tunable rather than short.\r\n"
    "  const timeoutMs = Number(process.env.BLACKROSE_BRIDGE_TIMEOUT_MS ?? '') || 600_000\r\n"
    "  let res: Response\r\n"
    "  try {\r\n"
    "    res = await fetch(base.replace(/\\/$/, '') + route, {\r\n"
    "      method,\r\n"
    "      signal: AbortSignal.timeout(timeoutMs),",
    'jsonCall head')

rep(
    "    body: body === undefined ? undefined : JSON.stringify(body),\r\n"
    "  })\r\n"
    "  const text = await res.text()",
    "      body: body === undefined ? undefined : JSON.stringify(body),\r\n"
    "    })\r\n"
    "  } catch (e) {\r\n"
    "    if (e instanceof Error && (e.name === 'TimeoutError' || e.name === 'AbortError')) {\r\n"
    "      throw new Error(`bridge call timed out after ${Math.round(timeoutMs / 1000)}s: ${route}`)\r\n"
    "    }\r\n"
    "    throw e\r\n"
    "  }\r\n"
    "  const text = await res.text()",
    'jsonCall tail')

open(P, 'wb').write(c.encode('utf-8'))
print('BRIDGE TIMEOUT APPLIED')
