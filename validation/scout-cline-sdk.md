# Agent-Runtime Scout — Cline SDK (`@cline/sdk`) adopt-vs-build

- **Task:** task_0005 — "Agent-runtime scout: Cline SDK adopt-vs-build"
- **Date:** 2026-10-02
- **Status:** ASSESSMENT ONLY — read-only. No repo files changed, nothing installed, no migration proposed as approved.
- **Method:** read the BlackRose runtime source (cited per item) + the loaded `cline-sdk` skill + official docs at docs.cline.bot/sdk. SDK facts are cited; anything I could not confirm from those two sources is marked **UNVERIFIED**.
- **Question:** should BlackRose replace or augment its hand-rolled agent runtime with the Cline SDK, and at what cost?

> **RECOMMENDATION (one line):** **Option (c) — DO NOT ADOPT the SDK as a runtime dependency.** Keep the hand-rolled runtime and borrow named *patterns*. The SDK duplicates capabilities BlackRose already has (GREEN), while adopting it would (1) break the zero-runtime-dependency promise, (2) put the free-first `openai<N>` router chain behind a provider layer BlackRose would no longer own, and (3) import a **fail-open** approval default that contradicts BlackRose's fail-closed rule.

---

## 1. Interface Mapping

BlackRose concept | Cline SDK equivalent | Gap
--- | --- | ---
| `runAgent()` loop — `src/core/agent.ts:153` | Direct `Agent` / `AgentRuntime` (`run`/`continue`/`abort`) **or** `ClineCore.start()` | BlackRose returns `{ messages, text, turns, usage, trimmed }`; SDK `Agent` returns `result.outputText` + usage. Different return contract, not a drop-in. |
| Callbacks `onText` / `onToolCall` / `onToolResult` — `agent.ts:14-16` | **Two different event systems** (skill rule #7): `agent.subscribe()` → `AgentRuntimeEvent` (`assistant-text-delta`, `tool-started`, `tool-finished`, `run-finished`) vs `cline.subscribe()` → `CoreSessionEvent` / host `AgentEvent` (`content_start`, `content_update`, `content_end`, `iteration_start/end`, `usage`, `notice`, `done`, `error`) | Different shapes and different subscribe entry points for `Agent` vs `ClineCore`. BlackRose's web UI (`src/ui/web/server.ts`) consumes its own callbacks — would need an adapter either way. |
| `buildTool()` + `TOOL_DEFAULTS` fail-closed default — `src/core/tools.ts:40-51` | `createTool({ name, description, inputSchema, execute`) | SDK `createTool` accepts **raw JSON Schema** (docs.cline.bot/sdk/tools) — BlackRose's `input_schema` is JSON Schema, so the *shape* maps cleanly. **But defaults are inverted:** SDK tool policies "default to enabled and auto-approved" (fail-OPEN); BlackRose's `requiresApproval` default returns `null` only because state-changing tools must override it, and the design intent is fail-closed. |
| `requiresApproval(input, ctx)` per-input declarative gate — `tools.ts:36` | `toolPolicies: { name: { autoApprove, enabled } }` (per-tool) + `capabilities.requestToolApproval(request)` (dynamic, `request.toolName`/`request.input`) | BlackRose gates per-*call* declaratively in the tool; SDK gates per-*tool* by policy or dynamically by callback. Behaviourally close; default policy direction differs (see above). |
| `ToolContext` (`cwd`, `dataDir`, `askApproval`, `log`, `runSubTask`) — `tools.ts:10-25` | `config.cwd` / `config.workspaceRoot`; `capabilities.requestToolApproval` | No `dataDir` equivalent; SDK session storage is its own. No direct `runSubTask` field. |
| `LlmClient` provider abstraction — `src/llm/client.ts:13` | `@cline/llms` gateway (`providerId`/`modelId`/`apiKey`/`baseUrl`; `openai-compatible`) | SDK's gateway **is** the provider layer. Using `Agent`/`ClineCore` means running on the SDK's provider model. A custom `AgentModel` can be supplied to `AgentRuntime` — whether BlackRose's `LlmClient` can be bridged to it is **UNVERIFIED**. |
| Free-first numbered `openai1…openai9` gateway routes + `routerClient` fallback — `src/llm/router.ts:18`, `src/llm/factory.ts:55-69` | `providerId: "openai-compatible"` + `baseUrl` (one provider) | **No equivalent.** The SDK has provider catalogs and a gateway, not an ordered, health-tracked, multi-gateway fallback chain. This is BlackRose's differentiator and has no SDK counterpart. |
| Route health registry (`routeHealth.ts`), key rotation + key health (`router.ts:58`, `keyHealth.ts`) | none | **No equivalent.** Would be lost if the runtime moved onto the SDK provider layer. |
| `runGoal` task engine (goal → plan → execute → verify → report) — `src/core/taskEngine.ts:52` | none first-class (sub-agents / teams exist, but no plan/execute/verify engine) | Remains app-level custom code regardless. |
| `spawn_agent` depth-1 sub-agent — `src/tools/agentTool.ts:9`, host `runSubTask` | `config.enableSpawnAgent` (sub-agents) / `enableAgentTeams` (teams) | SDK sub-agents are parent→child within a session; teams add cross-session persistence (`~/.cline/data/teams/<name>/task-board.json|mailbox.json|mission-log.json`). BlackRose enforces depth-1 by withholding `runSubTask` from the child ctx — simple and sufficient today. |
| Scheduler `startScheduler` (interval tick, crash-safe, **fail-closed unattended**) — `src/schedule/runner.ts:32,53-65` | ClineCore "scheduling and automation APIs" + cron (docs.cline.bot/sdk/clinecore) | SDK cron semantics and unattended-approval behaviour **UNVERIFIED**. BlackRose's unattended auto-deny (`BLACKROSE_SCHEDULE_APPROVE` opt-in) is bespoke and matches fail-closed. |
| Session persistence `src/session/history.ts` (JSON/session) + encrypted `.aistate` `src/state/aistate.ts` (AES-256-GCM, portable) | ClineCore session artifacts: `manifestPath`, `messagesPath` (plain files) | BlackRose's encrypted, portable `.aistate` has no SDK equivalent. |
| System prompt builder — `src/llm/prompt.ts` | `config.systemPrompt` | Compatible (plain string). |
| Permissions policy + workspace path policy — `src/core/permissions.ts` | `toolPolicies` + `requestToolApproval` + workspace root | Partially overlapping; BlackRose's path policy (writes outside workspace require approval) is app-level custom. |
---

## 2. Fit Analysis (against the project's non-negotiable values)

### 2.1 Zero runtime dependencies — **DOES NOT FIT**
BlackRose ships with **no runtime dependencies** today (`package.json` has only `devDependencies`: `@tauri-apps/cli`, `@types/node`, `typescript`; `engines.node >=24`). Every SDK import — even `@cline/shared` for `createTool` — pulls a transitive tree (`@cline/sdk` → `@cline/core` → `@cline/agents` / `@cline/llms` / `@cline/shared`). That is a direct conflict with a stated non-negotiable. Adding *any* part of the SDK is a policy change, not a refactor.

### 2.2 Model independence / free-first `openai<N>` chain — **AT RISK**
The crown jewel (`factory.ts` numbered gateway routes, `router.ts` ordered fallback, `routeHealth.ts` tray, `keyHealth.ts` rotation) is a bespoke ordered, health-tracked, multi-gateway chain. The SDK models providers as `providerId`/`modelId` (+ `openai-compatible` + `baseUrl`) with a gateway — **one provider at a time; no health-tracked ordered fallback chain, no numbered multi-gateway multiplexing** (docs.cline.bot/sdk/model-providers). Adopting `ClineCore` wholesale means the runtime runs on the SDK provider layer and the router chain must be re-expressed *inside* it (or bypassed) — the exact thing the project forbids. This is the single strongest argument against option (a).

### 2.3 ~25 MB single Windows installer — **COST**
Every dependency must be bundled into the Tauri self-contained Node runtime, the SDK's transitive tree grows the bundle. Exact MB **UNVERIFIED** (I deliberately did not install or fetch package sizes). Directionally additive: a zero-dep app that bundles only its own `src` gains a `node_modules` tree — non-zero, one-way.

### 2.4 Privacy / fail-closed approvals — **CONFLICT**
BlackRose is fail-closed: `buildTool` defaults + unattended scheduler auto-deny (`runner.ts:56-63`). The SDK's tool policies **default to enabled and auto-approved** (docs.cline.bot/sdk/tools; docs.cline.bot/sdk/guides/permission-handling). Adopting it means re-imposing fail-closed on top of a fail-open default — doable via `toolPolicies`/`requestToolApproval`, but it inverts the project's safest assumption into an opt-in.

### 2.5 Node version — **FITS**
SDK requires Node >=22; BlackRose requires >=24. Compatible; no conflict.

### 2.6 What the SDK would actually *add* over BlackRose
The SDK's headline features are built-in tools (read/search/run/apply_patch/editor), session persistence, approvals, sub-agents/teams, scheduling. Per the capability audit (`validation/audit-capabilities.md`), BlackRose already has these GREEN: task engine, model failover, context optimization, scheduler, permissions, secret vault, undo, `.aistate`. The overlap is high and the marginal gain is small — the SDK mostly *replaces working, verified, self-owned code* with a dependency.

---

## 3. Options, cost & benefit

### (a) ADOPT `ClineCore` wholesale for the runtime
- **Cost:** Add `@cline/sdk` + transitive tree to a zero-dep app; grow the ~25 MB installer; rewrite the runtime onto the SDK provider layer, **discarding** the numbered `openai<N>` chain, route health, key rotation and fail-closed default; re-implement BlackRose's `runGoal` / `.aistate` / path policy on top; re-plumb the web-UI event model to `CoreSessionEvent`.
- **Benefit:** Gain Cline's built-in tool suite, session artifacts and teams "for free"; less code to own.
- **Verdict:** Violates three stated non-negotiables (zero-dep, model independence, fail-closed). **Reject.**

### (b) ADOPT SELECTIVELY — SDK tool/hook/event *types* + sub-agent delegation; keep BlackRose's router/approval/persistence
- **Cost:** Still adds a dependency (any SDK import breaks zero-dep). Only the *types* + delegation helpers are reused, so the router/approval/persistence stay BlackRose's — but you now carry a dependency for type ergonomics and a sub-agent helper you already have (`spawn_agent`/`runSubTask`, `src/tools/agentTool.ts`).
- **Benefit:** Cleaner typed events/tools; SDK-maintained sub-agent delegation; borrow the completion-tool idea and the host-facing event taxonomy.
- **Verdict:** The *pattern* borrowing is good; the *dependency* is the problem. This option only becomes correct if the project **relaxes the zero-dep rule**. Until then, take the patterns (option c) without the import.

### (c) DO NOT ADOPT — keep hand-rolled runtime; borrow specific patterns
- **Cost:** Near-zero. No dependency, no installer growth, no provider-layer lock-in, fail-closed default preserved. Cost is "we keep maintaining our own loop" (already GREEN and verified).
- **Benefit:** Preserves every non-negotiable; keeps the router chain and approval semantics exactly as designed.
- **Patterns worth stealing (named):**
  1. **Completion tools** — `lifecycle: { completesRun: true }` (skill rule #5; exact field name **UNVERIFIED**) gives a deterministic loop terminator vs BlackRose's implicit "text-only turn ends the run" (`agent.ts:215`).
  2. **Host-facing event taxonomy** — `content_start/update/end`, `iteration_start/end`, `usage`, `notice`, `done/error` (docs.cline.bot/sdk/events) → formalize `onText`/`onToolCall`/`onToolResult` into a typed event union for the SSE stream in `ui/web/server.ts`.
  3. **Team persistence shape** — `task-board.json` / `mailbox.json` / `mission-log.json` per team (docs.cline.bot/sdk/guides/multi-agent-teams) → a concrete file layout for BlackRose team tooling; feeds the audit's #1/#2 blockers (Executive Brain B12, learning engine B16/B17).
  4. **`snapshot()` runtime introspection** (events doc) → a read-model for the web control plane without reaching into loop internals.
  5. **Declarative tool-policy map** `{ autoApprove, enabled }` (docs.cline.bot/sdk/tools) → adopt the *shape* for UI-driven policy, but keep BlackRose's fail-closed default (invert SDK default to `{ autoApprove: false }`).
  6. **Structured recoverable tool-error results** (skill rule #4) → already partly present (`errResult`, `agent.ts:39`); formalize so the model recovers rather than the loop treating errors as fatal.
---

## 4. Recommendation

**Single recommended option: (c) DO NOT ADOPT the SDK as a runtime dependency — keep the hand-rolled runtime and borrow the named patterns above.**

Justification (one sentence): The SDK's headline capabilities are ones BlackRose already owns and has verified GREEN, while adopting it would simultaneously break the zero-runtime-dependency promise, displace the free-first numbered `openai<N>` router/health chain that is the project's model-independence core, and import a fail-open approval default — three non-negotiables traded for code BlackRose does not need.

**Condition that would flip the decision:** if the project ever relaxed the zero-dep rule, the SDK's elegant parts are shared types + sub-agent/event ergonomics, so **option (b)** would become the right choice — never (a), because (a) still forfeits the router chain and fail-closed default.

## 5. Minimal Spike Sketch (only if (b) is ever considered) — do NOT write into the repo

Throwaway dir **outside** the repo: `$env:TEMP\cline-sdk-spike\` (Windows). No repo files touched, no secrets.

```
%TEMP%\cline-sdk-spike\
  package.json      { "type": "module", "dependencies": { "@cline/sdk": "*" } }
  probe-tool.ts     copy ONE BlackRose JSON-Schema tool (read_file from src/tools/files.ts)
                    into createTool({ name, description, inputSchema: <raw JSON schema>, execute })
  probe-agent.ts    new Agent({ providerId: "openai-compatible", modelId, apiKey:"" ,
                      baseUrl: "http://127.0.0.1:20128/v1" })   // existing local OmniRoute route
                    agent.subscribe(e => log(e.type))            // observe AgentRuntimeEvent
                    await agent.run("list files in cwd")         // force a tool call
  probe-size.ps1    measure node_modules count + MB (npm ls --all --parseable | measure)
```

**Acceptance check (all must pass to justify (b)):**
1. `createTool` accepts BlackRose's raw JSON Schema unmodified and the model triggers it (`tool-started` / `tool-finished` observed).
2. The `openai-compatible` + `baseUrl` provider reaches the existing local gateway without new credentials.
3. `probe-size.ps1` reports the transitive dependency count and MB — the number that decides whether zero-dep can be relaxed.
4. Explicitly observe the **default** approval behaviour of a write tool with **no** `toolPolicies` set (confirm the fail-open default and measure the work to re-impose fail-closed).

If (1)–(4) are not cheap, that is itself the answer: option (c).

## 6. Pydantic AI — does it fit? (short)

No. Pydantic AI is a **Python** framework, while BlackRose is a Node/TypeScript, zero-runtime-dependency app shipped as a single ~25 MB Windows installer bundling a self-contained Node >=24 runtime. Adopting it would mean bundling (or requiring) a Python interpreter, inflating the installer well past 25 MB and breaking the one-installer/no-deps promise, and splitting the codebase across two languages. It does not fit and is not worth pursuing.

---

## 7. Appendix — Evidence & Citations

**BlackRose source read (all under `C:\Users\pc\Desktop\BlackRose\cline\blackrose\`):**
- `src\core\agent.ts` (loop, `trimHistory`, `errResult`, usage accounting) — lines 14-16, 39, 153, 215, 232-239.
- `src\core\taskEngine.ts` (`runGoal`: plan→execute→verify) — line 52.
- `src\core\tools.ts` (`buildTool`, `TOOL_DEFAULTS`, `ToolContext.runSubTask`) — lines 10-25, 36, 40-51.
- `src\tools\agentTool.ts` (`spawn_agent`, depth-1) — line 9.
- `src\llm\router.ts` (`routerClient`, `rotatingKeyClient`) — lines 18, 58.
- `src\llm\factory.ts` (numbered `openai<N>`, `KEYLESS_ROUTES`) — lines 28-69, 183-226.
- `src\schedule\runner.ts` (fail-closed unattended) — lines 32, 53-65.
- `package.json` (zero runtime deps; `node >=24`).

**Cline SDK (loaded `cline-sdk` skill + docs.cline.bot):**
- Node >=22; packages `@cline/sdk` → `@cline/core` → `@cline/agents`/`@cline/llms`/`@cline/shared` — docs.cline.bot/sdk/overview.
- `createTool` raw JSON Schema accepted; tool policies default to enabled + auto-approved — docs.cline.bot/sdk/tools.
- `requestToolApproval` callback + `toolPolicies` — docs.cline.bot/sdk/clinecore, docs.cline.bot/sdk/guides/permission-handling.
- Two event systems (`AgentRuntimeEvent` vs `CoreSessionEvent`) — skill rule #7; docs.cline.bot/sdk/events.
- Provider model (`providerId`/`modelId`/`apiKey`/`baseUrl`, `openai-compatible`, `DefaultGateway`) — docs.cline.bot/sdk/model-providers.
- Sub-agents vs teams + team persistence paths — docs.cline.bot/sdk/guides/multi-agent-teams.
- ClineCore session artifacts `manifestPath`/`messagesPath` — docs.cline.bot/sdk/clinecore.

**Marked UNVERIFIED:** SDK transitive dependency size/MB; whether a BlackRose `LlmClient` can be bridged to an SDK `AgentModel`; SDK cron/unattended-approval semantics; exact `lifecycle` field spelling.