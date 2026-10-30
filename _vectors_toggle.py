import sys

P = r'src\memory\vectors.ts'
c = open(P, 'rb').read().decode('utf-8')
mode = sys.argv[1]

INV = (
    "  // ONE PERSISTED INDEX = ONE VECTOR SPACE (2026-10-26, NEXT WORK item 9).\r\n"
    "  // A mixed 3072/256-d store under one header silently poisons cosine()\r\n"
    "  // (it truncates to Math.min length, so similarity degrades to garbage\r\n"
    "  // instead of failing) and poisons every future batch that reuses the\r\n"
    "  // cached entries. The stranded-re-embed guard in vectorsFor keeps fresh\r\n"
    "  // inserts coherent; this is the backstop that holds the line at\r\n"
    "  // persistence no matter how the in-memory map got mixed.\r\n"
    "  if (store.file.dim > 0) {\r\n"
    "    let droppedMixed = 0\r\n"
    "    for (const id of Object.keys(store.file.entries)) {\r\n"
    "      if (decode(store.file.entries[id]!.v).length !== store.file.dim) {\r\n"
    "        delete store.file.entries[id]\r\n"
    "        droppedMixed++\r\n"
    "      }\r\n"
    "    }\r\n"
    "    if (droppedMixed > 0) {\r\n"
    "      console.warn(\r\n"
    "        `[vectors] dropped ${droppedMixed} cross-space vector(s) before saving — ` +\r\n"
    "        `the index stays one ${store.file.dim}-d space.`,\r\n"
    "      )\r\n"
    "    }\r\n"
    "  }\r\n"
)

STRANDED_GUARD = (
    "        const coherent = again.model === res.model && again.dim === res.dim\r\n"
)
STRANDED_WARN = (
    "        if (!coherent) {\r\n"
    "          console.warn(\r\n"
    "            `[vectors] stranded re-embed landed in a different space (${again.model} ${again.dim}-d vs ` +\r\n"
    "            `${res.model} ${res.dim}-d) — served from memory, not cached, so one index stays one space.`,\r\n"
    "          )\r\n"
    "        }\r\n"
)
STRANDED_IF = "          if (coherent) {\r\n"

if mode == 'revert':
    # remove the saveStore invariant
    a = INV := None  # placeholder
    assert INV is None or True
import re
if mode == 'revert':
    c = open(P, 'rb').read().decode('utf-8')
    assert c.count(STRANDED_MARK := 'stranded same-space guard') == 0
    # remove invariant block
    i = c.index('  // ONE PERSISTED INDEX = ONE VECTOR SPACE')
    j = c.index('  const ids = Object.keys(store.file.entries)')
    c = c[:i] + c[i:].replace(
        c[c.index('  // ONE PERSISTED INDEX'):c.index('  const ids = Object.keys(store.file.entries)')],
        '', 1)
    # make the stranded insert unconditional again
    c = c.replace('        const coherent = again.model === res.model && again.dim === res.dim\r\n', '')
    c = c.replace('        if (!coherent) {\r\n          console.warn(\r\n            `[vectors] stranded re-embed landed in a different space (${again.model} ${again.dim}-d vs ` +\r\n            `${res.model} ${res.dim}-d) — served from memory, not cached, so one index stays one space.`,\r\n          )\r\n        }\r\n', '')
    c = c.replace('          if (coherent) {\r\n            store.file.entries[s.id] = {\r\n              v: Buffer.from(new Float32Array(v).buffer).toString(\'base64\'),\r\n              h: textHash(s.text),\r\n            }\r\n          }\r\n', '          store.file.entries[s.id] = {\r\n            v: Buffer.from(new Float32Array(v).buffer).toString(\'base64\'),\r\n            h: textHash(s.text),\r\n          }\r\n')
    open(P, 'wb').write(c.encode('utf-8'))
    print('REVERTED')
else:
    print('unknown mode')
    sys.exit(1)
