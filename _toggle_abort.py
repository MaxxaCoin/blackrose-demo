import sys

P = r'src\tools\telegram.ts'
c = open(P, 'rb').read().decode('utf-8')
mode = sys.argv[1]
if mode == 'revert':
    a = "const res = await fetchNoTimeout(url, opts.signal ? { signal: opts.signal } : undefined)\r\n"
    b = "const res = await fetchNoTimeout(url)\r\n"
    assert c.count(a) == 1
    c = c.replace(a, b)
    a = "      pollAbort.abort() // cut the in-flight long poll: the event loop can drain\r\n"
    assert c.count(a) == 1
    c = c.replace(a, '')
else:
    assert mode == 'restore'
    a = "    const res = await fetchNoTimeout(url)\r\n"
    b = "    const res = await fetchNoTimeout(url, opts.signal ? { signal: opts.signal } : undefined)\r\n"
    assert c.count(a) == 1
    c = c.replace(a, b)
    a = "      roleLock.lock.release()\r\n    },\r\n"
    b = "      roleLock.lock.release()\r\n      pollAbort.abort() // cut the in-flight long poll: the event loop can drain\r\n    },\r\n"
    assert c.count(a) == 1, c.count(a)
    c = c.replace(a, b)
open(P, 'wb').write(c.encode('utf-8'))
print(mode.upper() + ' OK')
