"""NEXT WORK item 9 (vectors): one persisted index = one vector space.

(A) vectorsFor: the stranded re-embed (`again`) can land in a DIFFERENT backend
    than `res` (quota exhaustion between the two calls). Serving stays total,
    but only same-space vectors are cached into the store.
(C) saveStore: persistence invariant — any entry whose decoded length
    disagrees with the header dim is dropped before the write, so a mixed
    3072/256-d index can never reach disk.
"""
import sys

P = r'src\memory\vectors.ts'
c = open(P, 'rb').read().decode('utf-8')


def rep(old, new, label):
    global c
    n = c.count(old)
    if n != 1:
        print(f'FAIL {label}: found {n}')
        sys.exit(1)
    c = c.replace(old, new)
    print(f'ok {label}')


# A. stranded re-embed: serve from memory always, cache only same-space vectors
rep(
    "      const stranded = items.filter((it) => !missing.some((m) => m.id === it.id))\r\n"
    "      if (stranded.length > 0) {\r\n"
    "        const again = await embedBatch(stranded.map((s) => s.text))\r\n"
    "        stranded.forEach((s, i) => {\r\n"
    "          const v = again.vectors[i]!\r\n"
    "          fresh.set(s.id, v)\r\n"
    "          store.file.entries[s.id] = {\r\n"
    "            v: Buffer.from(new Float32Array(v).buffer).toString('base64'),\r\n"
    "            h: textHash(s.text),\r\n"
    "          }\r\n"
    "        })\r\n"
    "      }\r\n",
    "      const stranded = items.filter((it) => !missing.some((m) => m.id === it.id))\r\n"
    "      if (stranded.length > 0) {\r\n"
    "        const again = await embedBatch(stranded.map((s) => s.text))\r\n"
    "        // 2026-10-26 NEXT WORK item 9: this second call can land in a\r\n"
    "        // DIFFERENT space than `res` — the backend flaps between the two\r\n"
    "        // embeds (quota spent between them). Serving is fine (in-memory\r\n"
    "        // vectors are how the fallback survives), but inserting a 3072-d\r\n"
    "        // vector into a 256-d store (or the reverse) under one header builds\r\n"
    "        // a MIXED index, and cosine() silently truncates via Math.min, so\r\n"
    "        // ranking degrades to garbage instead of failing. Cache only\r\n"
    "        // same-space vectors; the odd ones are served for THIS call from\r\n"
    "        // memory and re-embedded on a later call.\r\n"
    "        const coherent = again.model === res.model && again.dim === res.dim\r\n"
    "        if (!coherent) {\r\n"
    "          console.warn(\r\n"
    "            `[vectors] stranded re-embed landed in a different space (${again.model} ${again.dim}-d vs ` +\r\n"
    "            `${res.model} ${res.dim}-d) — served from memory, not cached, so one index stays one space.`,\r\n"
    "          )\r\n"
    "        }\r\n"
    "        stranded.forEach((s, i) => {\r\n"
    "          const v = again.vectors[i]!\r\n"
    "          fresh.set(s.id, v)\r\n"
    "          if (coherent) {\r\n"
    "            store.file.entries[s.id] = {\r\n"
    "              v: Buffer.from(new Float32Array(v).buffer).toString('base64'),\r\n"
    "              h: textHash(s.text),\r\n"
    "            }\r\n"
    "          }\r\n"
    "        })\r\n"
    "      }\r\n",
    'stranded same-space guard')

# C. saveStore: the persistence invariant — no mixed-dim index ever hits disk
rep(
    "  const ids = Object.keys(store.file.entries)\r\n"
    "  if (ids.length > MAX_ENTRIES) {\r\n",
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
    "  const ids = Object.keys(store.file.entries)\r\n"
    "  if (ids.length > MAX_ENTRIES) {\r\n",
    'saveStore dim invariant')

open(P, 'wb').write(c.encode('utf-8'))
print('VECTORS FIX APPLIED')
