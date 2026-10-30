"""Clean pinnedLookup typed directly against net.LookupFunction."""
import sys

P = r'C:\Users\pc\Desktop\BlackRose\cline\blackrose\src\tools\knowledge.ts'
c = open(P, 'rb').read().decode('utf-8').replace('\r\n', '\n')

START = c.index('type PinnedLookupCb = (')
END = c.index('/**\n * Fetch an http(s) URL with the SSRF guard, shared by knowledge_ingest\n * (loadIngestText) and learn_url. Follows redirects MANUALLY, re-validating', START)

NEW = """function pinnedLookup(addrs: { address: string; family: number }[]): NonNullable<net.LookupFunction> {
  return (_hostname, options, callback) => {
    const fam = options?.family === 'IPv4' ? 4 : options?.family === 'IPv6' ? 6 : options?.family
    const usable = addrs.filter((a) => (fam ? a.family === fam : true))
    if (usable.length === 0) {
      const err = new Error('no validated address usable for this connection (pinned SSRF lookup)') as NodeJS.ErrnoException
      err.code = 'EAI_AGAIN'
      process.nextTick(() => callback(err))
      return
    }
    process.nextTick(() => {
      if (options?.all) {
        // all:true → callback(null, [{address, family}...])
        callback(null, usable)
      } else {
        callback(null, usable[0]!.address, usable[0]!.family)
      }
    })
  }
}

"""
c = c[:START] + NEW + c[START:]
# there is now a leftover duplicate doc comment? The replaced span ended right
# before the sha256 comment - nothing removed. Just write back.
open(P, 'wb').write(c.replace('\n', '\r\n').encode('utf-8'))
print('done')
