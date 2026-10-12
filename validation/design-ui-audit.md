# BlackRose UI — Design Audit and Redesign Direction

Author: Frontend Design Lead (UI remodel track)
Scope: read-only audit of the shipped web UI. No repo source was modified.
Sources cited: `cline/blackrose/src/ui/web/assets.ts` (2765 lines, the page as a TS
template literal), `cline/blackrose/src/ui/web/server.ts` (1385 lines, the /api
surface), `cline/blackrose/docs/04-ROADMAP.md`.

Companion file: `validation/ui-redesign-mockup.html` (standalone, working shell).

---

## 1. INVENTORY — what the shipped UI actually is

### 1.1 The emission model
The entire page is one TypeScript template literal. `uiHtml()` is at `assets.ts:2852`;
it concatenates the `CSS` const (`assets.ts:8`), the `BODY` const (`assets.ts:524`) and
an inline `<script>` (`assets.ts:2858`) closed at `assets.ts:2865`. There are no external
assets, no build step, no framework, no web fonts — deliberate, so the page survives Node
SEA / Tauri packaging (`assets.ts:1-5`). The parse guard is
`validation/check-ui-parse.mjs` (extracts the `<script>` and runs `new vm.Script` on it).

### 1.2 Layout system
A fixed two-zone flex shell, not a document (`assets.ts:26-40`):
- `body` is `flex-direction: column; height:100vh; overflow:hidden` — the window never scrolls.
- `header` (`assets.ts:41-55`): fixed height, no wrap, holds only the logo `BlackRose`
  (`assets.ts:526`) and a connection `dot` (`assets.ts:527`). The router string and route
  chips were explicitly evicted from here on 2026-09-30 (`assets.ts:44-51`).
- `#app` (`assets.ts:56`): `display:flex` row.
- `aside` (`assets.ts:57-65`): fixed `width:268px`, own scrollbar, `background:var(--bg2)`.
- `main` (`assets.ts:104`): `flex:1`, chat + composer column.
- `#chat` (`assets.ts:105`): scroll region, `padding:20px 26px`, bubble list.
- `#inputbar` (`assets.ts:186-226`): textarea + attach + mic + send + stop.

### 1.3 Sidebar — 9 `<details>` groups (`assets.ts:536-612`)
Each group is a `<details class="grp">` (`assets.ts:67-86`); open/closed is inline.

| Group | Line | Buttons / content | Endpoint(s) |
|---|---|---|---|
| Conversations (open) | 536-542 | New chat, `#session-list` | GET `/api/sessions`; POST `/api/sessions/open`, `/api/sessions/delete`, `/api/new` |
| Knowledge (open) | 543-553 | `#stats`, Learned sources, Forget a source, Search knowledge, Search memory, Project notes | GET `/api/health`; POST `/api/tool` (`knowledge_list`, `knowledge_forget`, `knowledge_search`, `memory_search`, `project_read`) |
| Workspace (open) | 554-561 | Run a goal, Normal chat mode, Clear conversation | POST `/api/goal`, `/api/ask`, `/api/new` |
| Automation | 562-570 | Skills, Scheduled missions, Background jobs, Tool catalogue | POST `/api/tool` (`skill_list`, `schedule_list`, `job_list`); GET `/api/tools` |
| Data | 571-577 | Export state, Import state | POST `/api/export`, `/api/import` |
| Settings | 578-584 | API keys and gateways, Trust mode | GET/POST `/api/keys`, `/api/keys/roster`, `/api/keys/validate`, `/api/keys/bulk`, `/api/keys/rotate`, `/api/providers`; GET/POST `/api/trust` |
| Connected routes | 588-596 | `#routes-model`, `#route-list`, Route details, Edit fallback chain | GET `/api/health` (`routes[]`); GET/POST `/api/routes` |
| System | 597-603 | Check for update, Shut down | Tauri updater bridge; shutdown bridge |
| Help | 604-612 | 4 static keyboard hints | none (static) |

### 1.4 Panels / overlays
Every "panel" is a centered modal over a dimmed backdrop; there is no routed page,
no persistent inspector, no side panel.
- `#overlay` approval dialog (`assets.ts:629-638`, z-index 90) — Allow/Deny.
- `#keys-modal` (`assets.ts:639`, z-index 58) — API key manager.
- `#provider-modal` (`assets.ts:655`) — add provider.
- `#chain-modal` (`assets.ts:709`) — fallback chain editor.
- `#forget-modal` (`assets.ts:731`) — forget a source + dedup scan.
- `#bulk-modal` (`assets.ts:753`) — bulk key import.
- `#panel` (`assets.ts:780-788`) — the generic "capability inspector": `<pre id="pn-body">`.
- `#launch` (`assets.ts:789-799`, z-index 60) — continue/launch chooser.
- `#modal` (`assets.ts:800-813`, z-index 30) — generic prompt (export pw, import, confirm).
- `#dropveil` (`assets.ts:625`, z-index 70) — full-window drag-and-drop veil.
- `#queue` (`assets.ts:624`) — queued messages.

### 1.5 Endpoints the page calls (from `fetch(` sites)
`/api/sessions` (978, 1032), `/api/sessions/delete` (993), `/api/sessions/open` (1001, 1040),
`/api/new` (1077, 1736, 1748), `/api/health` (1412), `/api/routes` (1535, 1573),
`/api/upload` (1616), `/api/listen` (1688), `/api/export` (1830), `/api/import` (1851),
`/api/tool` (1935, 1993, 2049, 2095), `/api/tools` (2127), `/api/trust` (2168, 2180),
`/api/providers` (2238, 2260), `/api/keys` (2337, 2622, 2649), `/api/keys/validate`
(2405, 2460), `/api/keys/bulk` (2427), `/api/keys/roster` (2478), `/api/keys/rotate`
(2553, 2588), plus `/api/ask|/api/goal` (2739), `/api/stop` (2816), `/api/approve` (2836).

Server route table confirmed at `server.ts:347-1240`; `/api/health` payload is
`{name, provider, model, memories, knowledgeChunks, schedules, skills, routes[]}`
(`server.ts:364-375`, `getRouteStates()` at `server.ts:16`).

### 1.6 Typography (the real type scale)
`assets.ts:13` mono: `ui-monospace, 'Cascadia Mono', 'Cascadia Code', Consolas, 'SF Mono', 'Roboto Mono'`.
`assets.ts:21` sans: `'Segoe UI Variable Text', 'Segoe UI', system-ui, -apple-system, 'Inter', Roboto, 'Helvetica Neue', Arial`.
`assets.ts:22` scale: `--fs-xs:11.5px --fs-sm:12.5px --fs-base:14px --fs-md:15px --fs-lg:17px`.
Body is `14px/1.6` (`assets.ts:28`). AI messages `15px`, measure `min(78%,68ch)`
(`assets.ts:112`). The comment at `assets.ts:14-20` explicitly refuses web fonts to
avoid a network dependency and a flash of invisible text.

### 1.7 Color tokens (`assets.ts:9-23`)
`--bg:#0d1117 --bg2:#161b22 --bg3:#1f2630 --border:#30363d --fg:#e6edf3 --dim:#8b949e
--accent:#e64c8d --accent2:#bc3f76 --ok:#3fb950 --warn:#d29922 --err:#f85149`.
Accent is a magenta/pink. Everything is one dark theme; there is **no light mode and no
`prefers-color-scheme` media query anywhere** in the file.

### 1.8 Motion
Exactly one animation in the whole product: `@keyframes mic-pulse` (`assets.ts:231-234`)
plus one `transition: transform .16s` on the group chevron (`assets.ts:82`). No page-load
choreography, no streaming-reveal, no panel enter/exit.

### 1.9 Voice/sound
`assets.ts:6` imports `approvalChimeDataUri` from `./sound.ts`; injected at
`assets.ts:2863` as `window.__APPROVAL_CHIME__`, played on approval events.

---

## 2. DIAGNOSIS — concrete aesthetic and UX problems

### D1. THE BIGGEST PROBLEM: every "panel" is a raw monospace text dump in a modal
`showPanel(title, text)` (`assets.ts:1924-1928`) writes a single string into
`<pre id="pn-body">` (`assets.ts:783`), styled `white-space: pre-wrap; font-family:
var(--mono)` (`assets.ts:475-480`). Every capability inspector reuses it: Skills
(`assets.ts:1966`), Missions (`1967`), Jobs (`1968`), Learned sources (`2117`), Project
notes (`2118`), Knowledge search (`2119`), Memory search (`2120`), Tool catalogue
(`2133`) and Route details (`1443`). So the entire surface meant to let the user *see what
the agent knows and can do* is the SAME preformatted text block inside the SAME centered
modal (`#panel`, `assets.ts:780-788`). No tables, no per-item rows, no actions, no
affordances — it is `console.log` rendered in a dialog. This is the worst UX outcome in
the product and the reason "inspecting" the agent feels pointless.

### D2. The knowledge / learned-sources panel cannot scale, and does not paginate
Learned sources is `bind('btn-klist', ..., 'knowledge_list', {})` (`assets.ts:2117`) which
runs `runTool` (`assets.ts:1930-1948`) → `showPanel` with the raw `j.content`
(`assets.ts:1941`). `#pn-body` caps at `max-height:56vh; overflow:auto`
(`assets.ts:478`) — one scrollable `<pre>`, NOT a paginated or virtualised list. A long or
sparse payload shows a wall of monospace; when little is ingested the box is near empty —
exactly the reported "0 knowledge chunks" experience. Grep confirms no pagination logic in
the panel path (no page/offset/limit tokens in the panel functions). `#stats`
(`assets.ts:1398-1409`) gives only 4 numbers (`Memories`, `Knowledge chunks`, `Schedules`,
`Skills`) from `/api/health` (`server.ts:368-374`) — no drill-down.

### D3. The route-status tray is wired but demoted behind a collapsed folder
The tray spec (`04-ROADMAP.md:385-388`; green=current, red=quota-out, yellow=needs
key/repair, in the TOP tray) IS implemented in data: `/api/health` returns `routes[]`
(`server.ts:374`, `getRouteStates()` at `server.ts:16`), and `paintRoutes`
(`assets.ts:1315-1393`) renders dot + name + model + state per route with the CORRECT
colours: `.route-row.ok` green (`assets.ts:273`), `.degraded` red (`274`), `.down` yellow
(`275`), `.unknown` dim (`277`). BUT it was moved OUT of the header into a sidebar
`<details>` (`assets.ts:588-596`) that opens **collapsed** (no `open`, unlike the first
three groups). So the one always-on health signal a long-running agent needs is hidden two
clicks deep. `routeSummary` (`assets.ts:1272-1280`) even computes a one-line rollup that
nothing surfaces at rest.

### D4. The palette is literally GitHub Dark with a pink accent bolted on
`assets.ts:10-12` is `#0d1117 / #161b22 / #30363d / #e6edf3 / #8b949e` — GitHub Dark
canvas/default/border/fg/muted — with `--accent:#e64c8d`. A borrowed, instantly
recognisable developer-tool skin, not a BlackRose identity. `--bg3:#1f2630` is a cold
blue-grey that fights the warm magenta accent; `--err/#f85149` and `--ok/#3fb950` are again
GitHub. Nothing expresses "a persistent intelligence layer I live in".

### D5. Typography is the default system stack — no voice at all
`--sans` (`assets.ts:21`) leads `'Segoe UI Variable Text'` then `system-ui`, `Inter`,
`Roboto`, `Arial`; `--mono` (`assets.ts:13`) is `ui-monospace/Cascadia/Consolas` — the
exact generic stack the discipline forbids. The scale is also collapsed: `--fs-xs:11.5` to
`--fs-lg:17` is 5 steps spanning 5.5px (`assets.ts:22`); `header .logo` is 16px
(`assets.ts:53`) vs body 14px (`assets.ts:28`). Hierarchy is unreadable from type, so the
user reads structure from boxes instead.

### D6. No light mode, no theme switch, no `prefers-color-scheme`
Grep for `@media` in `assets.ts` returns nothing; there is one `:root` block
(`assets.ts:9-23`) only. A tool the user lives in all day that is hard-locked to dark
ignores daylight use. Contrast inside it is also weak: `.msg.ai em { color:#c9d1d9 }`
(`assets.ts:115`) sits close to `--fg:#e6edf3`.

### D7. Almost no motion; the AI card is a flat box
Only `@keyframes mic-pulse` (`assets.ts:231-234`) and one chevron
`transition:transform .16s` (`assets.ts:82`) exist. AI messages are a flat `--bg3` box
with a 1px border and an asymmetric corner (`assets.ts:111-112`); streaming text, tool
events and approval prompts all appear with zero entrance, so a long-running agent looks
frozen while it works ("it is thinking" is invisible).

### D8. Every inspection result steals the whole screen
`#panel` is `position:fixed; inset:0` (`assets.ts:468-471`) — inspecting Skills destroys
your chat context. For a persistent assistant the inspector should dock beside the work,
not replace it.

### D9. Help lives in the sidebar as four static rows
`assets.ts:604-612` renders keyboard hints as `.stat` rows that compete with real
destinations in the same column. Documentation masquerading as navigation.

### D10. Requested destinations with NO real panel (Phase-8 ~20-destination list)
Verified by grepping the sidebar (`assets.ts:536-612`) and the `bind`/`bindQ` set
(`assets.ts:1966-2133`):

| Requested destination | Real panel? | Evidence | Endpoint / backend it would need |
|---|---|---|---|
| Missions | YES (raw text) | `assets.ts:566`, `1967` | `POST /api/tool {name:'schedule_list'}` (exists) |
| Skills | YES (raw text) | `assets.ts:565`, `1966` | `POST /api/tool {name:'skill_list'}` (exists) |
| Knowledge | PARTIAL | `assets.ts:543-553`, `2117-2120` | `/api/tool` knowledge_* (exists); needs paginated listing |
| Tools | YES (raw text) | `assets.ts:568`, `2123-2133` | `GET /api/tools` (exists) |
| Settings | PARTIAL | `assets.ts:578-584` | `/api/keys`, `/api/trust` (exists); NO permissions editor |
| Agents | **NO** | no sidebar entry, not in bind set | NEW `GET /api/agents` (+ `spawn_agent` history) — backend change |
| Learning | **NO** | learn_* excluded by allowlist (`04-ROADMAP.md:59-63`) | NEW allowlist entry + `POST /api/tool {name:'learn_status'}` — backend change |
| Models | **NO** (badge only) | `#routes-model` `assets.ts:591` | NEW `GET /api/models` (selectable models) — backend change |
| Computer | **NO** | `gui_action`/screenshot not in allowlist | NEW read-only `computer_status` tool + allowlist — backend change |
| Browser | **NO** | no browser tool exists in repo | NEW browser tool + endpoint — backend change, large |

`routes` is referenced 52 times and IS rendered (D3), so the tray is not missing — it is
demoted. `#panel` (`assets.ts:780`) is the only overlay container for inspection.

---

## 3. DESIGN DIRECTION — "NIGHT GARDEN LEDGER"

One named, cohesive direction. BlackRose is a rose: dark, botanical, thorned, patient. A
persistent intelligence layer the user lives in all day is not a dashboard you glance at —
it is a garden you tend and a ledger you trust. The design language is **warm ink and
bone**, not cold GitHub navy; a **living spine** of system state down the left edge; and a
single **reading column** where the agent speaks in a literary serif.

### 3.1 Typography — three voices, three jobs
No system stack, no Inter/Roboto/Arial. Three real faces, self-hosted as local `.woff2`
(a local file, not a CDN — flagged as the ONE change needing user approval, because the
file currently ships zero web fonts by design at `assets.ts:14-20`):
- **Fraunces** (variable, "wonky" optical-size serif) — the brand/display voice. Logo,
  panel titles, day/date stamps. Its thorns-and-petals contrast is the personality the
  current `'Segoe UI Variable Text'` (`assets.ts:21`) has none of.
- **Newsreader** (variable literary serif) — the agent's speaking voice. All AI prose
  (`.msg.ai`, `assets.ts:111-112`) set at 17px/1.7 with a `62ch` measure. Prose in a
  reading serif is why long answers stop reading as "a wall" (`assets.ts:14-20`).
- **JetBrains Mono** — the machine voice. Keys, route names, token counts, tool output
  (replaces `--mono`, `assets.ts:13`).
Type scale widens from 5.5px of range (`assets.ts:22`) to a true modular scale:
`--fs-2xs:10.5 --fs-xs:11.5 --fs-sm:13 --fs-base:15 --fs-md:17 --fs-lg:21 --fs-xl:27
--fs-2xl:36`. Headings now outrank body by more than 2px.

### 3.2 Colour — the Night Garden palette (replaces GitHub Dark)
Token NAMES stay identical to `assets.ts:9-12` so the rest of the page needs no changes;
only values change.
- `--bg:#14110F` warm ink (not `#0d1117` cold navy) · `--bg2:#1C1815` · `--bg3:#262019`
- `--border:#3A322A` (thistle) · `--fg:#EDE6DA` (bone) · `--dim:#9A8F80` (ash)
- `--accent:#C8436A` botanical rose (deeper than `#e64c8d`) · `--accent2:#8E2D4C`
- `--ok:#7FA650` moss · `--warn:#D8A13A` amber · `--err:#C9553D` rust
The warm ground cuts the blue-grey/magenta clash of D4; the status trio is no longer
GitHub's.

### 3.3 Spatial concept — the Ledger and the Bloom
Two zones, asymmetric, not a card grid:
- **The Ledger** — a 300px left rail that never fully disappears. Its top is the
  **living spine**: one vertical glowing dot per gateway route, always visible (fixes D3 —
  the tray stops being a collapsed folder). Below it: sessions, knowledge counts, skills.
  Hovering a ledger row cross-highlights the matching message in the column.
- **The Bloom** — the reading column. The agent speaks as continuous prose in Newsreader,
  not in bubbles; user turns are a thin bone rule + label, like a margin note, so the
  transcript reads as one document the user scrolls through, not a chat log.
- The inspector docks INSIDE the rail (fixes D1/D8): selecting Skills/Knowledge/Tools
  swaps the rail body to a real, rowed, paginated list — never a full-screen `#panel` text
  dump.
Generous negative space: 26px column gutters, a 1px thistle rule where the old UI drew
14px-radius grey boxes.

### 3.4 Signature interaction — "The Bloom"
When the agent works, a light travels down the living spine and each finished step leaves
a small petal-mark in the margin of the Bloom; the active route dot "breathes" slowly.
This is the ONE orchestrated motion (replacing scattered micro-interactions, D7) and it is
the whole point: a long-running agent must *look alive* without stealing focus. It also
respects `prefers-reduced-motion` (static dot instead).

### 3.5 Light / dark strategy — two gardens, one token set
Same token names; two value sets. **Night Garden** (above) is the default. **Day Garden**:
`--bg:#F4EFE6` paper, `--bg2:#FBF7EF`, `--bg3:#EAE2D4`, `--border:#D8CCBA`,
`--fg:#241E17`, `--dim:#6E6355`, `--accent:#B0355A` (rose darkened for paper contrast).
Default follows `prefers-color-scheme` (currently absent entirely, D6) and a manual toggle
persists to `localStorage`. Because only `:root` values differ, no layout or component CSS
changes between themes.

### 3.6 Why it fits a tool the user lives in all day
Calm warm ground lowers fatigue over hours; a real reading serif makes long agent answers
comfortable; a permanent health spine means a quota-out or a dead key is visible without
hunting; and "The Bloom" makes the agent legible as alive. It is distinctive (Fraunces +
Newsreader + JetBrains Mono is nobody's default), cohesive (one metaphor: garden/ledger),
and honest to the product's name.

---

## 4. REMEDIATION PLAN — prioritized, mapped to real endpoints

| # | Item | What to build | /api/* it needs | Backend change | Effort |
|---|---|---|---|---|---|
| 1 | **Replace the text-dump panel (D1)** | Turn `showPanel`'s `<pre>` into a real rowed list renderer; Skills/Missions/Jobs/Tools each get rows, counts, and actions | `POST /api/tool` (`skill_list`, `schedule_list`, `job_list`), `GET /api/tools` (all exist) | No | M |
| 2 | **Dock the inspector in the rail (D1/D8)** | Stop `#panel` covering `inset:0`; render inspection results inside the ledger rail so chat context survives | same as #1 | No | M |
| 3 | **Paginate + row-render Learned sources (D2)** | Real list: source, chunks, learned-at, per-row Forget; client-side pagination + a search box | `POST /api/tool {name:'knowledge_list', input:{limit,offset}}` | **Yes** — `knowledge_list` must accept `limit/offset` | M |
| 4 | **Promote the living spine / route tray (D3)** | Always-visible vertical dot spine from `/api/health routes[]` at the rail top; click opens Route details inline (not a modal) | `GET /api/health`, `GET/POST /api/routes` (exist) | No | S |
| 5 | **Night Garden palette + token swap (D4)** | Replace the 11 colour-token values in `assets.ts:10-12`; keep names | none | No | S |
| 6 | **Type system (D5)** | Fraunces + Newsreader + JetBrains Mono self-hosted; widen the scale | none (needs 3 local `.woff2` files — **user approval**, breaks the "zero web fonts" rule at `assets.ts:14-20`) | No (assets only) | M |
| 7 | **Ledger + Bloom layout (D5/D8)** | Asymmetric 300px rail + reading column; AI turns as Newsreader prose, user turns as margin rules; drop the bubble boxes | none | No | L |
| 8 | **"The Bloom" signature motion (D7)** | Traveling spine light + margin petal-marks + breathing active dot; gate on `prefers-reduced-motion` | none | No | M |
| 9 | **Light/dark switch (D6)** | `prefers-color-scheme` default + a persisted manual toggle (Day Garden values) | none | No | S |
| 10 | **Move Help out of navigation (D9)** | A `?` affordance opening a small sheet; free the sidebar slot | none | No | S |
| 11 | **Agents panel (D10)** | New destination: list spawned sub-agents and their status | NEW `GET /api/agents` | **Yes** — endpoint + `spawn_agent` history | L |
| 12 | **Learning panel (D10)** | New destination: what has been learned and when | NEW `POST /api/tool {name:'learn_status'}` + allowlist entry (roadmap `04:59-63` restricts it) | **Yes** — allowlist + tool | M |
| 13 | **Models panel (D10)** | New destination: select/reorder the active model, not just a badge | NEW `GET /api/models` | **Yes** | M |
| 14 | **Permissions editor (D10)** | UI over the always-ask rules currently only in `trust.ts` | `GET/POST /api/trust` (exists) — needs a richer payload | **Yes** — expose rule list | M |
| 15 | **First-run setup wizard (gap)** | Guide: pick provider -> add key -> verify -> first chat | `GET /api/providers`, `POST /api/keys/validate`, `GET /api/keys/roster` (exist) | No (state signal desired) | M |
| 16 | **Computer / Browser panels (D10)** | Very large; leave unwired until a real read-only status tool exists | NEW tools + endpoints | **Yes** — large | L |

### Sequencing recommendation
Ship 1-5 first (they fix the visible problems with NO backend change beyond #3), then 6-10
(the full "Night Garden Ledger" visual system), then the backend-gated destinations 11-16
only as each endpoint genuinely exists — honoring the project rule at
`04-ROADMAP.md:51-63`: integrate real endpoints rather than fake UI buttons.

### Hard constraints honored by this plan
Read-only audit — no file in the repo was edited. Zero new runtime dependencies (Fraunces/
Newsreader/JetBrains Mono are local assets, flagged for approval). No key or env value is
printed. Every diagnosis cites an `assets.ts` or `server.ts` line. Any page-string code
shown avoids escaped apostrophes and uses doubled `\\n`, per the template-literal trap
(`assets.ts:1429-1430`) and the guard `validation/check-ui-parse.mjs`.

---

---

