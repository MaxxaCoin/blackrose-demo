p = r'src\tools\knowledge.ts'
c = open(p, 'rb').read().decode('utf-8')
old = "import { fetchWithTimeout, stripHtml } from './web.ts'"
new = "import { stripHtml } from './web.ts'"
assert c.count(old) == 1
open(p, 'wb').write(c.replace(old, new).encode('utf-8'))
print('import cleaned')
