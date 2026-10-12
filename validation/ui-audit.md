# BlackRose Web UI — Correctness Audit (Part A) + Visual Direction Spec (Part B)

Auditor: ui-audit teammate · Repo: `cline/blackrose` · File under audit: `src/ui/web/assets.ts`
(2930 lines, emits HTML+CSS+JS as **strings**, served by `src/ui/web/server.ts`).
**Constraint honoured throughout: no imports, no CDN links, no external font URLs, no framework, no
build step.** `grep` for `https://fonts|fonts.googleapis|cdn\.|@import` over `assets.ts` → **0 hits**.

---

## PART A — CORRECTNESS

### A1. State → colour mapping: **PASS, no inversion**

`assets.ts:264-278`

```css
.route-row .rd { background: var(--dim); }                       /* unknown → grey */
.route-row.ok       .rd { background: var(--ok);   }               /* GREEN  #3fb950 */
.route-row.degraded .rd { background: var(--err);  }               /* RED    #f85149 */
.route-row.down     .rd { background: var(--warn); }               /* YELLOW #d29922 */
.route-row .rn { color: var(--fg) }
.route-row.ok       .rn { color: var(--ok);   }
.route-row.degraded .rn { color: var(--err);  }
.route-row.down     .rn { color: var(--warn); }
.route-row.unknown { opacity: .72; }
.route-row.unknown .rn { color: var(--dim); }
```

Cross-checked against the legend in `src/llm/routeHealth.ts:6-9` and the comment at
`server.ts:417-418` ("ok=green, degraded=red quota-out, down=yellow needs-attention"). The
deliberately-inverted convention is honoured exactly: **green=ok, red=degraded (quota-out,
self-recovering), yellow=down (needs a human), grey=unknown**. The state dot *and* the route
name both carry the colour, so the state survives a colourblind reader and a greyscale print.
No inversion bug.

### A2. `unknown` excluded from the "not ok" count: **PASS**

`assets.ts:1285-1293`

```js
const ok  = routes.filter(r => r.state === 'ok').length;
// unknown is NOT "not ok" — it means not probed yet, or a gateway that hides
// /models. Counting it as a failure made a healthy chain look broken.
const bad = routes.filter(r => r.state === 'degraded' || r.state === 'down').length;
```

The fix is genuinely in place and correctly scoped: `bad` counts only `degraded`/`down`.
`unknown` is neither counted as ok nor as bad — it is simply not "not ok", which is the
intent. Output shape `"N routes · M ok · K not ok"` reads correctly for an all-unknown tray
(`"8 routes · 0 ok"`), which is exactly the healthy-but-unprobed case the comment describes.

### A3. Zero routes + the embed-degraded banner: **PASS**

- **Zero routes** — `assets.ts:1337-1343` clears the list and emits `#routes-empty` =
  *"No gateway routes reported — using the direct provider."* The initial static markup
  (`:605`) ships the same id with *"reading gateway routes…"*, so there is no blank flicker.
  `showRouteDetails()` (`:1469`) independently prints *"(none — the direct provider is in
  use)"*. Covered.
- **Embed-degraded (B5)** — `assets.ts:1427-1441`, inside `paintStats(h)`, which runs on every
  30 s health poll. It fires on `h.embed.degraded` and distinguishes the three cases:
  `quotaExhausted → "quota spent"`, `indexMismatch → "rebuilding"`, else `"lexical only"`; the
  value is coloured `var(--warn)` and the row carries a `title` explaining that retrieval is
  keyword-only and that `scripts/warm-embed.ts` re-indexes. Payload source is
  `embedHealth(dataDir)` at `server.ts:169-190`, wired at `server.ts:422`.
  **Honest caveat:** this banner is a row inside the *Knowledge* sidebar group, not the route
  tray. It is present, correct and always-on (that `<details>` is `open`), but a user scanning
  only "Connected routes" will not see it. Part B proposes surfacing it there too — as a
  **taste decision, not applied.**

### A4. XSS — the route tray is clean; **two real sinks found and fixed elsewhere**

**Route tray: SAFE.** Every provider-controlled string reaches the DOM as `textContent`, never
`innerHTML` (`assets.ts:1353` name, `:1358` model, `:1364` detail). The tooltip is the DOM
`title` **property** (`:1367-1368`), which is not parsed as markup. `showRouteDetails()` builds
a string and hands it to `showPanel()`, which assigns `pnBody.textContent` (`:1959`) — a plain
text sink. `list.innerHTML = ''` at `:1336` is a clear, not a write. **No route name, model or
upstream error detail is ever interpolated into HTML.** This was the highest-risk item and it
holds.

Two genuine raw-HTML sinks elsewhere in the page, both now escaped (fixes applied, see A6):

1. `assets.ts:2738` (was `:2733`) — the keys-panel catch-all did
   `keysList.innerHTML = '…⚠ Error: ' + e.message`. `e.message` originates from a `/api/keys`
   **server error body** and from upstream provider validation text; it is attacker-influenceable
   and lands in a raw-HTML sink. → wrapped in `escHtml()`.
2. `assets.ts:2446-2447` — `bulkProvider.innerHTML = '<option value="' + envVar + '">' +
   (routeName || envVar) + '</option>'`. `routeName` is a custom-provider name the user types
   when adding a gateway, so a name like `"><img src=x onerror=…>` broke out of both the
   attribute and the text node. → both parts wrapped in `escHtml()`. The pre-existing sibling at
   `:2139` was already correct, which is why the pattern is now consistent.

**Residual, deliberately NOT changed (reported, not fixed):** `assets.ts:1420`
`d.innerHTML = '<span>' + k + '</span><b>' + v + '</b>'` in `paintStats`. `k` is a literal and
every `v` is a server-computed **count** (`h.memories`, `h.knowledgeChunks`, `h.schedules`,
`h.skills`, `h.embed.indexed`) — all numbers on the current server. It is a latent sink only if a
future field becomes free text; changing it would mean rewriting the stat loop for no current
defect, so I left it and am flagging it instead.

### A5. Duplicate rows (`name::model` vs `name::''`): **ALREADY FIXED upstream — no duplicate risk**

`routeHealth.ts:20-22` keys on `` `${name}::${model ?? ''}` ``. The old divergence is gone:
both writers now share **one** derivation, `routeEntriesFromClient(name, model)`
(`routeHealth.ts:134-142`), whose comment states exactly this invariant:

> *"This is what stops the tray growing two rows per route: the prober used to re-derive the
> model from `BLACKROSE_<NAME>_MODEL ?? ''` while registerRoute used the router's real model,
> so one route produced two differently-keyed entries. One derivation, used by both, cannot
> drift."*

Verified at both call sites:
- `server.ts:16` imports it; `server.ts:268-269` pre-registers
  `for (const r of routeEntriesFromClient(o.client.name, o.client.model)) registerRoute(r.name, r.model)`.
- `ui/web/main.ts:12` imports **the same function**; `main.ts:102` iterates
  `routeEntriesFromClient(client.name, client.model)` and threads that `model` into every
  `recordRouteProbe(..., model)` call (`:108, :118, :123, :126`).

Same function, same pairing → a probe lands on the existing row. **The tray cannot render a
route twice.** (The `openai1[3 keys]` display-name renaming in `factory.ts:79-81` is
name-preserving via `bare` for env lookup while `name` stays the registered route name, so it
does not fork the key either.)

### A6. Fixes applied (Part A only — 3 edits, all surgical, all in existing terse style)

1. **`assets.ts:1346-1351` — state whitelist (correctness).**
---

## PART A — VERBATIM GATE OUTPUT (post-fix)

```
$ node scripts/check-modals.ts
  ok    a shared .hidden rule exists (1 found)
  ok    keys-modal: startsHidden=true perIdRule=true
  ok    provider-modal: startsHidden=true perIdRule=false (covered by the shared rule)
  ok    chain-modal: startsHidden=true perIdRule=false (covered by the shared rule)
  ok    forget-modal: startsHidden=true perIdRule=false (covered by the shared rule)
  ok    bulk-modal: startsHidden=true perIdRule=false (covered by the shared rule)
PASS
EXIT=0
```

```
$ node scripts/check-pagescript.ts
  ok    the served page script parses
  ok    bold
  ok    inline code
  ok    fenced code
  ok    unordered list
  ok    ordered list
  ok    heading
  ok    blockquote
PASS
EXIT=0
```

```
$ node scripts/check-richtext.ts
  ok    bold + italic
  ok    h1-h6
  ok    bullets
  ok    slash bullets
  ok    numbered
  ok    mixed list types
  ok    prose paragraphs
  ok    blockquote
  ok    rule
  ok    orphan bold
  ok    orphan star tail
  ok    multiplication preserved
  ok    underscores in identifiers
  ok    url with underscore
  ok    inline code
  ok    fenced code
  ok    link
  ok    strikethrough
  ok    xss attempt
  ok    bare asterisk line
  ok    realistic messy answer
PASS
EXIT=0
```

```
$ npx tsc --noEmit
EXIT=0
```

**All four gates green. The three UI gates were also run BEFORE the edits and were green then,
so the fixes introduced no regression.** (`node src/smoke.ts` was not run here — it exceeds the
30 s command budget because it performs live route probes; it is the route-health teammate's
gate. A trial run printed only the expected benign stderr warning `[embed] Gemini daily
---

## PART B — "NIGHT GARDEN" visual direction (SPEC ONLY — NOT APPLIED)

### B0. The thesis

A **night greenhouse that is also an instrument panel.** Two surfaces, one discipline:

- **Botanical** — deep desaturated greens, warm brass/gold accents, generous negative space.
  The glass is dark and the light is low, warm, and directional.
- **Observatory** — a strict typographic hierarchy, tabular numerals, hairline rules, small-caps
  section labels, and *legended* status colour. Nothing glows for decoration.

**Explicitly not:** neon cyberpunk, glassmorphism, purple/cyan gradients, glow-shadows on
everything, or a "hacker terminal" green-on-black. The current `--accent: #e64c8d` hot-pink plus
`box-shadow` glow is the thing being replaced.

### B1. Palette — exact CSS custom-property values

Contrast ratios below are **computed** (WCAG 2.x relative-luminance formula), not estimated.
Targets: body text ≥ 4.5:1, large text / icons / borders ≥ 3:1.

```css
:root {
  /* -- surfaces: four planes, each a real step in depth (not one grey reused) -- */
  --bg:    #070d0b;   /* page ground — near-black with a green cast, never pure #000 */
  --bg2:   #0c1512;   /* sidebar, header, panels */
  --bg3:   #122019;   /* cards: stat rows, chain rows, route rows */
  --bg4:   #182a20;   /* raised: hover, open <details>, selected */

  /* -- ink: warm off-white, never #fff (it glares on a dark page) -- */
  --fg:    #e8f0e4;
  --dim:   #9db3a4;   /* secondary body text — still >= 4.5:1 on all four surfaces */
  --faint: #6f8a79;   /* tertiary / metadata ONLY; 4.02:1 on --bg4, so never use
                         it for body copy or for a control label */

Measured contrast (foreground on surface):

| on → | `--bg` | `--bg2` | `--bg3` | `--bg4` |
|---|---|---|---|---|
| `--fg` `#e8f0e4` | **16.81** | **15.92** | **14.45** | **12.95** |
| `--dim` `#9db3a4` | **8.79** | **8.32** | **7.56** | **6.77** |
| `--accent` `#7fd6a2` | **11.24** | **10.64** | **9.66** | **8.66** |
| `--accent2` `#c8a24a` | **8.14** | **7.71** | **7.00** | **6.27** |
| `--ok` `#7ee0a4` | **12.21** | **11.56** | **10.50** | **9.41** |
| `--warn` `#e8c07d` | **11.45** | **10.84** | **9.84** | **8.82** |
| `--err` `#f0a08c` | **9.44** | **8.94** | **8.11** | **7.27** |
| `--unk` `#7d9186` | **5.85** | **5.54** | **5.03** | **4.51** |

Every status colour clears **4.5:1 on every surface** (9.41 worst case), so status text is
body-text-grade, not large-text-only. `--faint` is the one exception and is scoped to metadata
at ≥ 4.02:1 — documented above so it is a choice, not an oversight. `--border-strong`
(3.20–4.15:1) is the one that carries a meaning (a control's edge); `--border` stays decorative.

Note the deliberate choice: the status hues are **desaturated and warm** (a red at `#f0a08c` is
a terracotta, not a fire-engine red) so a wall of failing rows reads as *weather*, not as an
emergency. Saturation is spent only on `--accent`/`--accent2`, which is where the brand lives.
  /* -- accent: living green (primary) + brass (secondary, links + focus) -- */
### B2. Typography — **verified present on this machine**, no CDN

I checked the Windows font registry rather than assuming. Availability below is what this
machine actually reported (`registered=True` from the shell font namespace):

1. **Display / UI — `Georgia`, then `Constantia`, then `Cambria`.** All three ship with Windows
   and are **registered here**. A transitional serif for headings, the section summaries, and
   the "BlackRose" wordmark — it reads *botanical print / specimen label*, exactly the
   night-greenhouse register, and it is the single biggest step away from "generic".
   `Constantia` is the more distinctive of the two (old-style figures, a warm hand) and prefers
   `Palatino Linotype` as the fallback.
2. **Body — `Corbel`, then `Candara`, then `'Segoe UI'`.** All registered. `Corbel` is a
   humanist sans with a large x-height and open apertures — legible at the 11–13 px sizes the
   sidebar uses, where `Segoe UI` already strains. Keep `'Segoe UI'` **last** as the universal
   fallback.
3. **Mono / instrument — `'Cascadia Code'`, then `'Cascadia Mono'`, then `Consolas`.** Cascadia
   is **installed and registered here**, and is already first in the current `--mono` stack.
   Cascadia ships ligatures and a real tabular set, which is what the route-detail column and the
   model ids need. `Consolas` is registered (it ships with Windows even though no matching
   filename was present under `C:\Windows\Fonts` on this image), so keep it as the safety net.

**Honest negatives.** `Segoe UI Variable` and `Aptos`/`Aptos Display` are **NOT present** on
this machine, even though the current `--sans` stack lists `'Segoe UI Variable Text'` first — so
that entry is currently dead weight and should be dropped, not relied on. There is **no CDN**,
so web-only families (Inter, IBM Plex, Fraunces, Literata, Cormorant) are **unavailable without
bundling**, and bundling means committing ~200–400 KB of WOFF2 into this hand-written file with
no build step to minify or subset it — which fights the zero-dependency constraint.
**Recommendation: use only Windows-shipped families, ship nothing, and accept that the aesthetic
comes from the palette + hierarchy rather than from an exotic face.** If the user later wants a
bundled serif, the only clean path is a base64 `@font-face` in the CSS string for a *subset* of
the glyphs actually used (Latin basic + punctuation, ~20–30 KB), which is a decision to escalate,
not to take here.

```css
--serif: Georgia, Constantia, 'Palatino Linotype', Cambria, 'Times New Roman', serif;
--sans:  Corbel, Candara, 'Segoe UI', system-ui, -apple-system, sans-serif;
--mono:  'Cascadia Code', 'Cascadia Mono', Consolas, ui-monospace, 'SF Mono', monospace;
```

### B3. Concrete changes — sidebar route tray

Current markup (`assets.ts:1344-1405` + CSS `254-287`) is a flat 8 px-radius row on `--bg3` with
a glowing dot. Proposed:

1. **Left state rail instead of a floating dot.** Replace the 8 px glowing `.rd` circle with a
   3 px full-height bar on the row's left edge, `background: var(--ok|--err|--warn|--unk)`, and
   remove the `box-shadow` glow entirely — the glow is the cyberpunk tell and it also bleeds
   colour onto the adjacent text. The bar reads at a glance in a 268 px column and survives
   greyscale (it is a *position* cue as well as a hue cue).
2. **Name in the display serif, 13 px, `--fg` — no longer status-coloured.** Today `.rn`
   inherits the status hue. Colouring the *name* means the whole row shouts. Keep colour on the
   rail + the status *word*; let the name be ink. Then add the status word as a small-caps 10 px
   label: `OK` / `DEGRADED` / `DOWN` / `UNKNOWN` — which also means the state no longer depends
   on colour perception at all (an accessibility win, not just an aesthetic one).
3. **Model and detail become one dim two-line block**, `--mono` 10.5 px, `--dim`, with `detail`
   clamped to 2 lines (`-webkit-line-clamp: 2`) instead of today's single-line ellipsis — the
   detail string carries the actionable text (`missing API key — set BLACKROSE_X_API_KEY`,
   `HTTP 404 · gateway hides /models — unknown, not broken`) and today it is truncated to
   nothing useful.
4. **Key count moves into the row as a quiet pip**, replacing the `keys 3` button label with a
   brass `◆3` chip; the buttons keep their labels. A number is easier to scan than a word.
5. **Hover = `--bg4`, no border colour change.** Selected row gets a 1 px `--border-strong` left
   edge. 8 px radius → 6 px (less "app tile", more "instrument label").
6. **`#routes-empty` becomes an explicit state, not grey text:** centre it, `--faint`, italic
   serif, with the reason ("no gateway routes configured — the direct provider is in use").
7. **Keep the semantics.** Green=ok / red=degraded / yellow=down / grey=unknown, exactly as
   verified in A1. The redesign must not be the thing that inverts them.

### B4. Concrete changes — embed-degraded banner

Today (`assets.ts:1427-1441`) it is a `.stat` row with `--warn` text inside the Knowledge group —
indistinguishable from a number.

1. **Promote it to a real banner**, its own element above the stat list: `--bg3` ground, 1 px
   `--border-strong` left edge in `--warn`, 6 px radius, two lines — **"Search is running
   lexical-only"** (`--fg`, 13 px, `--sans`) and **"Gemini's daily embedding quota is spent —
   retrieval matches keywords until it resets."** (`--dim`, 11.5 px). The current copy hides the
   *reason* in a `title` tooltip; the whole point of B5 visibility is that this must be readable
   without hovering.
2. **Use `--warn`, not `--err`.** Per the documented legend, yellow means "needs a human", and
   this genuinely does (wait for the quota, or run `node scripts/warm-embed.ts`). A red banner
   would break the established semantics.
3. **Name the remedy inline** as a small monospace chip `node scripts/warm-embed.ts` — the user
   can copy it, and it distinguishes the quota-exhausted case from the `indexMismatch`
   "rebuilding" case.
4. **Mirror it into the route tray** as a single pinned row at the top of `#route-list` when
   `h.embed.degraded`, so someone reading only "Connected routes" still learns that retrieval is
   degraded. **This is the one change that crosses the A3 caveat** — proposed, not applied.
   Implementation would be ~6 lines inside `paintRoutes`, reusing the same `textContent`
   discipline as the route rows.
5. **Add the legend to the always-on UI.** `routeSummary()` already computes the rollup but it
   is only shown in the "Route details" panel (`assets.ts:1464`). Surfacing the same
   `"8 routes · 6 ok · 1 not ok"` line in the section summary would make the panel optional
   reading rather than required reading.

### B5. What I deliberately did not do

- **Did not reskin.** Not one colour value, font stack, radius or shadow in `assets.ts` changed
  as part of Part B. That decision is the user's.
- **Did not add imports, `@import`, CDN links, external font URLs, or a framework.** Verified by
  grep: 0 hits.
- **Did not run `git commit`.** The three Part-A fixes are in the working tree only, for the
  lead to review alongside the route-health teammate's commits.
Type scale (ratio ≈ 1.2, anchored at 13 px so nothing shrinks):

```
h1 20/1.25 600 --serif      section summary 11px 600 --sans uppercase tracking .12em
h2 17/1.3  600 --serif      body 13px/1.6 --sans      meta 11px/1.45 --sans --dim
code 12px  --mono          numerals: font-variant-numeric: tabular-nums
```
  --accent:  #7fd6a2;
  --accent2: #c8a24a;

  /* -- status. SAME SEMANTICS AS TODAY, deliberately inverted where documented.
        Renamed, NOT re-meaning: ok=GREEN, degraded=RED (quota-out, self-recovers),
        down=YELLOW (needs a human), unknown=GREY. Only the hue changes. -- */
  --ok:   #7ee0a4;    /* green  */
  --warn: #e8c07d;    /* yellow — "needs a human", NOT "bad" */
  --err:  #f0a08c;    /* red    — "self-recovering", NOT "fatal" */
  --unk:  #7d9186;    /* grey   — not probed yet */

  /* -- lines -- */
  --border:       #2b4436;  /* hairline separators, decorative only (1.6–1.9:1) */
  --border-strong:#4e7d66;  /* CONTROL borders — 3.20–4.15:1, meets 1.4.11 */
  --focus:        #c8a24a;  /* focus ring */
}
```
embedding quota is exhausted … Falling back to the hash embedder`.)
   `row.className = 'route-row ' + (r.state || 'down')` meant a **missing** `state` field
   painted the row **yellow/"down" = "needs a key or a fix"** — asserting human action is
   required for a route we know nothing about. Also, `r.state` was interpolated into a
   `className`; a value like `"ok evil"` would smuggle extra classes. Now whitelisted against the
   four known states with `unknown` as the fallback (grey = not probed yet), which is what the
   legend and the A2 comment both intend.
2. **`assets.ts:2738-2741`** — `escHtml()` the server error message (A4.1).
3. **`assets.ts:2446-2447`** — `escHtml()` the env var and provider name (A4.2).

Net diff: `src/ui/web/assets.ts | 16 ++++++++++------` → **12 insertions, 4 deletions**, one
file. No behavioural change to layout, copy, polling, or state derivation. The reskin is **NOT**
applied — that remains the user's taste call.