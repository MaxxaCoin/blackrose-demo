set -e
cd "C:/Users/pc/Desktop/BlackRose/cline/blackrose"
git add src/tools/knowledge.ts src/audit-sweep2.test.ts
git commit -m "fix: the SSRF guard's validated IPs are pinned to the connect - DNS rebinding is dead (release follow-up)" -m "The guard resolved the host with dns.promises.lookup and validated the answer, then handed the URL to fetch - which resolved the SAME hostname a second time inside net.connect (undici -> net.connect -> dns.lookup). Attacker DNS with TTL 0 answers public to query #1 and 127.0.0.1 to query #2: reproduced live end-to-end pre-fix, with learn_url delivering an internal loopback page into the knowledge base while the guard saw 93.184.216.34.

Node's fetch exposes no lookup hook (undici #421) and undici itself violates the zero-dep rule, so the guarded fetch now goes through node:http/https.request, whose lookup option reaches net/tls.connect. The hook answers ONLY from the validated array: no second, independent resolver query exists, so rebinding and multi-A hop-picking have nothing to attack. The URL keeps its hostname form, so TLS SNI and the certificate check still see the real host. The owner's allowLoopbackFetch capability (authenticated bookmarklet) is unchanged - it resolves normally and is pinned by its own test, which proves the new request path works end-to-end. Timeout is env-tunable (BLACKROSE_FETCH_TIMEOUT_MS, empty = unset, junk = default, same honest handling as BLACKROSE_MAX_TURNS).

Tests: the rebind test patches BOTH resolver answers exactly as attacker DNS would (public to the guard, loopback to the connect) and asserts the loopback service is never reached and no internal content is learned - proven to FAIL against the pre-fix code (the loopback WAS reached). audit-sweep2 10/10; tsc 0.

FLAGGED, not fixed (out of this item's scope): web_fetch (src/tools/web.ts) still plain-fetches arbitrary URLs with redirect-following and NO SSRF guard at all - the same class, a bigger hole than this residual. Recorded in the checkpoint for the owner." | head -3
git log --oneline -3
