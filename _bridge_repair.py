"""Repair the broken fetch block: rebuild it with the verbatim authorization line."""
import sys

P = r'src\bridge\client.ts'
c = open(P, 'rb').read().decode('utf-8')

# extract the actual authorization line from the current file
auth_line = None
for line in c.split('\r\n'):
    if 'authorization' in line:
        auth_line = line.strip()
        break
if not auth_line or 'token' not in auth_line:
    print('FAIL: authorization line not found/redacted')
    sys.exit(1)

start = c.find('  let res: Response')
end = c.find('  const text = await res.text()')
if start == -1 or end == -1 or end < start:
    print(f'FAIL anchors: start={start} end={end}')
    sys.exit(1)

block = (
    "  let res: Response\r\n"
    "  try {\r\n"
    "    res = await fetch(base.replace(/\\/$/, '') + route, {\r\n"
    "      method,\r\n"
    "      signal: AbortSignal.timeout(timeoutMs),\r\n"
    "      headers: {\r\n"
    "        'content-type': 'application/json',\r\n"
    "        " + auth_line + "\r\n"
    "      },\r\n"
    "      body: body === undefined ? undefined : JSON.stringify(body),\r\n"
    "    })\r\n"
    "  } catch (e) {\r\n"
    "    if (e instanceof Error && (e.name === 'TimeoutError' || e.name === 'AbortError')) {\r\n"
    "      throw new Error(`bridge call timed out after ${Math.round(timeoutMs / 1000)}s: ${route}`)\r\n"
    "    }\r\n"
    "    throw e\r\n"
    "  }\r\n"
)

c = c[:start] + block + c[end:]
open(P, 'wb').write(c.encode('utf-8'))
print('ok: fetch block rebuilt (auth line reused verbatim)')
