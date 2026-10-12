# Route-health probing — defect report

Commit `f9cd84f` on `main` (clean tree). 5 files, +216 / −35.

## Finding 1 — the prober re-derived the base URL from the environment alone

**Root cause.** `src/ui/web/main.ts` `probeRoutes()` read
`process.env['BLACKROSE_' + up + '_BASE_URL']` and nothing else, then did
`if (!key || !base) continue`. That is a *third* copy of the resolution rules:
`factory.ts` knows the openai default (`DEFAULT_OPENAI_BASE` = openrouter),
the keyless specs (`KEYLESS_ROUTES.kilo/ovh`), the vault provider registry
(`readProviders`), and the vault keys (`readProviderKeys`) — none of which the
prober saw. So any route relying on a built-in default was skipped, and the
keyless routes were skipped unconditionally because they have no key by design.

**Fix.** `factory.ts` exports `routeProbeTarget(name, dataDir): RouteProbeTarget | null`
next to the code it was duplicating: openai\* via `openAiEnv` + `readProviderKeys`,
keyless via `KEYLESS_ROUTES`, custom via `readProviders`, `null` for
anthropic/gemini/onemin (no OpenAI-compatible `/models` surface). `main.ts` calls
it instead of reading env. One resolver, two callers, cannot drift.

## Finding 2 — a hidden `/models` was classified as a route failure

**Root cause.** `recordRouteProbe(..., false, 'HTTP 404')` ran the detail through
`classifyRouteFailure`, whose auth branch matches `40[134]` → `down` → YELLOW
"needs attention". The comment directly above `probeRoutes` said the opposite:
*"a gateway that hides /models simply reports unknown, which is honest."* The code
contradicted its own stated intent.

**Fix.** New `classifyRouteProbe()` in `routeHealth.ts`: `^HTTP 40[45]` → `unknown`
with the reason in the detail; falls through to `classifyRouteFailure` otherwise.
`recordRouteProbe` now also refuses to let an *inconclusive* probe (`unknown`)

## Test output (verbatim)

```
npx tsc --noEmit
TSC_EXIT=0
```

```
node src/smoke.ts
  PASS — route-status tray: router records per-route ok/degraded/down states
  PASS — route probe: a gateway that hides /models (404/405) stays unknown, not down
  PASS — route probe: a route with no API key is reported down, never ok
  PASS — route probe: keyless routes resolve their base URL from KEYLESS_ROUTES (no key needed)
  PASS — route probe: probe and registerRoute produce one row per route (no duplicates)
  PASS — ui health exposes routes[] for the route-status tray
  ...
  workspace: C:\Users\pc\AppData\Local\Temp\blackrose-smoke-QRRVZJ
SMOKE TEST PASSED
```

```
passLines=207
failLines=0
```

```
node --test src/regression.test.ts
ℹ tests 51
ℹ suites 0
ℹ pass 51
ℹ fail 0
ℹ cancelled 0
ℹ skipped 0
ℹ todo 0
ℹ duration_ms 54591.499
```

## Smoke total changed: 203 → 207

Baseline measured before the edits was **203 PASS / 0 FAIL**. The 4 added checks,
all seeded with `resetRouteHealth()`:

1. `a gateway that hides /models (404/405) stays unknown, not down`
2. `a route with no API key is reported down, never ok` (fail-closed)
3. `keyless routes resolve their base URL from KEYLESS_ROUTES (no key needed)` —
   also asserts `openai` resolves a non-empty default base, pinning finding 1
4. `probe and registerRoute produce one row per route (no duplicates)`

No existing check was changed or removed; all 203 still pass.

erase a state a real call proved — the existing "keep a real `answering`" guard
only covered that one case.

## Finding 3 — key mismatch produced two tray rows per route

**Root cause.** `server.ts` `registerRoute(n, models[i])` keyed on the router's
**real** model (`o.client.model.split(' → ')`). `probeRoutes` computed
`model = process.env['BLACKROSE_'+up+'_MODEL'] ?? ''` and keyed on that. With the
model unset the probe wrote `name::''` — a different registry key, so the tray
showed the route twice, one permanently stuck at `unknown`.

**Fix.** `routeEntriesFromClient(name, model)` in `routeHealth.ts` is now the
single derivation of the `(name, model)` pairs a composed client represents.
Both `server.ts` `startWebUi` and `main.ts` `probeRoutes` use it, so a probe
updates the registered row instead of creating a second one. (It also trims, and
defaults a missing model to `''` the same way on both sides.)

## Finding 4 — the CLI path has NO route probing at all

**Confirmed, and it is not a bug in the prober — the prober simply does not run
there.** `routeHealth.ts` references appear only in `router.ts` (records real
call outcomes), `factory.ts`, `ui/web/main.ts`, `ui/web/server.ts`, and `smoke.ts`.
`src/index.ts` contains zero references to `routeHealth`, `probeRoutes`,
`recordRouteProbe`, `routeEntriesFromClient`, or `routeProbeTarget`.

So on `node src/index.ts` (no `--ui`), route health is learned **only** from real
router traffic via `recordRouteSuccess`/`recordRouteFailure`, and nothing is ever
read back — there is no `/api/health` endpoint and no tray in the CLI. Routes never
picked keep no state at all. That is consistent with the registry's documented
purpose ("the UI remodel's route-status-tray backend"), and `src/doctor.ts` already
covers one-shot CLI diagnostics, so I left it read-only. Noted here so it is a
recorded decision, not an oversight.

## Fail-closed behaviour

A keyed route with no key is now reported `down` with the env var named
(`missing API key — set BLACKROSE_OPENAI1_API_KEY`) instead of being silently
skipped, and can never read `ok`. Keyless routes send **no** `Authorization`
header, because those gateways 401 on a placeholder bearer token.

No new dependencies. No new probe type: still one `GET <base>/models` per route
on the same 120s timer, off the request path. No chat/completions probe.

## Diff summary

| File | Change |
|---|---|
| `src/llm/factory.ts` | +69 — `RouteProbeTarget`, `routeProbeTarget()` |
| `src/llm/routeHealth.ts` | +50/−13 — `classifyRouteProbe()`, probe writes via it, inconclusive-probe guard, `routeEntriesFromClient()` |
| `src/ui/web/main.ts` | +49/−35 — `probeRoutes` rewritten on the two shared helpers |
| `src/ui/web/server.ts` | +16/−8 — `registerRoute` uses `routeEntriesFromClient()` |
| `src/smoke.ts` | +67 — 4 route-probe checks |
