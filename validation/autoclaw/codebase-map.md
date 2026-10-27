# BlackRose — codebase map

Target: `C:\Users\pc\Desktop\BlackRose\cline\blackrose`
Method: read-only inspection, 2026-10-27. No builds, no edits to the repo.
LOC = `Get-Content <file> | Measure-Object -Line` summed per directory (counts newline-terminated lines; ±a few per file vs. editor counts). File counts include `*.test.ts` and `smoke.ts` unless stated.

Overall size: **178 `.ts` files, 50,832 lines** in `src/` (131 of them non-test, non-smoke).

---

## 0. Summary

- Single-package ESM TypeScript project, **zero runtime dependencies** (`package.json` has no `dependencies` block at all), Node **≥24**, sources executed directly by Node's type-stripping (`"start": "node src/index.ts"`) — no transpile step for normal use.
- Everything lives under `src/`, split into 11 subdirectories plus 6 root modules. The center of gravity is `src/tools/` (18,472 lines, 36% of the tree).
- Four host surfaces share one agent core: CLI (`src/index.ts`), local web UI (`src/ui/web/`), remote bridge (`src/bridge/`), and a Tauri desktop shell (`desktop/tauri/`) that spawns the bundled core.
- Tool surface: **161 tools**, all registered in one array in `src/tools/index.ts`.
- Tests: `npm test` = `smoke.ts` (5,210 lines) + `node --test` over **43 of the 46** `*.test.ts` files.

---

## 1. `package.json`

| Field | Value |
|---|---|
| name / version | `blackrose` / `0.10.2` |
| type | `module` (ESM) |
| private | `true` |
| engines.node | `>=24` |
| dependencies | **none** (key absent) |
| devDependencies | `@tauri-apps/cli ^2.11.4`, `@types/node ^24.13.4`, `typescript ^5.9.3` |

Scripts (complete list, `package.json:9-21`):

| Script | Command | Note |
|---|---|---|
| `start` | `node src/index.ts` | CLI, interactive |
| `ui` | `node src/index.ts --ui` | web UI |
| `ask` | `node src/index.ts` | alias of `start` |
| `typecheck` | `node node_modules/typescript/bin/tsc --noEmit` | the only type gate |
| `test` | `node src/smoke.ts && node --test <43 files>` | see §6 |
| `scan:secrets` | `node scripts/scan-secrets.ts` | |
| `scan:history` | `node scripts/scan-history.ts` | |
| `verify:checkpoint` | `node scripts/verify-checkpoint.ts` | |
| `build:exe` | `node scripts/build-exe.ts` | SEA single-exe |
| `build:desktop` | `npm run build:exe && node scripts/build-desktop.ts` | Tauri NSIS |

**There is no `build` script and no `doctor` script.** "Doctor" exists only as `node src/index.ts --doctor` (`src/index.ts:152`), as `src/doctor.ts` (298 lines), and as the `doctor` tool.

---

## 2. `tsconfig.json`

```json
target ES2023 · module NodeNext · moduleResolution nodenext
allowImportingTsExtensions true · noEmit true · strict true
noUncheckedIndexedAccess false · verbatimModuleSyntax true
types ["node"] · skipLibCheck true · include ["src"]
```

- `noEmit: true` is why `typecheck` passes `--noEmit` redundantly and why `scripts/build-exe.ts` re-invokes `tsc` with explicit emit flags (`--outDir dist-build --rewriteRelativeImportExtensions ... --verbatimModuleSyntax false`).
- `allowImportingTsExtensions` + `verbatimModuleSyntax` explain the pervasive `import ... from './x.ts'` style.
- `strict` is on but `noUncheckedIndexedAccess` is deliberately off.

---

## 3. `src/` directory map

| Directory | Files | LOC | Responsibility | Key files (LOC) |
|---|---|---|---|---|
| `tools/` | 77 | **18,472** | Every agent-callable tool, one module per family, plus the single registry `buildTools()`. Also hosts large integrations (Telegram, knowledge base, inbox). | `telegram.ts` 3,005 · `knowledge.ts` 2,293 · `inbox.ts` 656 · `office.ts` 420 · `selfimprove.ts` 420 · `index.ts` 385 (registry) · `robots.ts` 357 · `custom.ts` 354 · `video.ts` 318 · `repo.ts` 285 |
| `ui/` | 7 | **7,403** | Terminal rendering plus the whole embedded web UI: HTTP server, HTML/CSS/JS as template strings, bookmarklet endpoint, icon writer. | `web/assets.ts` 4,069 (199 KB of embedded UI) · `web/server.ts` 2,409 (112 KB, ~40 `/api/*` routes) · `web/main.ts` 411 · `web/bookmarklet.ts` 337 · `ico.ts` 87 · `render.ts` 67 · `web/sound.ts` 23* |
| `core/` | 33 | **6,191** | The agent runtime and its guardrails: dispatch loop, approvals/trust, undo journal, policy ACL, audit ledger, keys/vault, budgets, teams, workflows, executive brain, plugins, process/job registry, task engine. | `undo.ts` 553 · `keys.ts` 428 · `plugins.ts` 355 · `agent.ts` 353 · `providers.ts` 319 · `video.ts` 295 · `vault.ts` 289 · `workflow.ts` 287 · `executive.ts` 286 · `budget.ts` 270 · `tools.ts` 102 (ToolDef contract) |
| `memory/` | 19 | **3,085** | Retrieval and document plumbing: TF-IDF, hashed + API embedders, vector index, hybrid fusion, knowledge graph, mastery/experiment stores, and zero-dep parsers (PDF/DOCX/XLSX/PPTX/EPUB/ZIP/OOXML/OCR/transcript). | `embedder.ts` 473 · `graph.ts` 431 · `mastery.ts` 288 · `vectors.ts` 284 · `ooxml.ts` 246 · `redact.ts` 199 · `experiment.ts` 187 · `pdf.ts` 176 · `zip.ts` 152 |
| `llm/` | 14 | **2,258** | Provider clients behind one `LlmClient` interface, model router with fallback, retry wrapper, route health, system prompt. | `factory.ts` 305 · `openai.ts` 298 · `gemini.ts` 286 · `onemin.ts` 250 · `routeHealth.ts` 223 · `router.ts` 142 · `client.ts` 128 (Anthropic + interface) · `prompt.ts` 100 · `resilient.ts` 60 · `mock.ts` 18 |
| `bridge/` | 4 | **1,120** | Token-authed HTTP daemon so other machines can drive this instance; `--bridge` (serve) and `--remote` (drive); fail-closed approvals. | `server.ts` 431 · `client.ts` 213 · `main.ts` 201 · `aki.test.ts` 275 |
| `mcp/` | 3 | **683** | MCP stdio client (JSON-RPC/ndjson) that turns external servers into `ToolDef`s; untrusted servers are approval-gated per call. | `client.ts` 516 · `fakeServer.ts` 54 · `client.test.ts` 113 |
| `session/` | 3 | **597** | Conversation persistence (one JSON per session, `--resume`, `/compact`) and secret redaction before write. | `history.ts` 294 · `redact.ts` 149 · `redact.test.ts` 154 |
| `state/` | 1 | **377** | `.aistate` portable encrypted state (AES-256-GCM, `BRSTATE1` header, gzip JSON, v2 incremental deltas). | `aistate.ts` 377 |
| `skills/` | 1 | **247** | Skill store: markdown + frontmatter, one file per skill in `~/.blackrose/skills/`. | `skills.ts` 247 |
| `schedule/` | 1 | **200** | Unattended scheduler; due tasks run through the agent with approvals denied unless `BLACKROSE_SCHEDULE_APPROVE=all`. | `runner.ts` 200 |

\* `web/sound.ts` is 23 lines but **128 KB** — an embedded base64 audio asset, not logic.

### Root-level `src/*.ts`

| File | LOC | Role |
|---|---|---|
| `smoke.ts` | 5,210 | End-to-end smoke suite against a mock LLM (`makeClient` mock provider), run first by `npm test`. |
| `regression.test.ts` | 1,923 | Regression suite (`node --test`). |
| `index.ts` | 933 | CLI entry: REPL, one-shot, `--goal`, `--resume`, `--ingest`, `--doctor`, `--bridge`, `--remote`, `--ui`; wires scheduler, auto-backup, inbox watch, MCP registration, Telegram watch. |
| `audit-fixes.test.ts` | 605 | Audit-fix regressions. |
| `parser-hostile.test.ts` | 320 | Hostile-input tests for document parsers. |
| `doctor.ts` | 298 | Keyless diagnostics behind `--doctor`. |
| `audit-sweep2.test.ts` | 204 | Second audit sweep. |
| `backup.ts` | 123 | Auto-backup bootstrap. |
| `config.ts` | 66 | Env-driven config; `dataDir` default `~/.blackrose` (`BLACKROSE_DATA_DIR` override). |
| `types.ts` | 44 | Wire-format message/tool-block types. |
| smaller tests | 473 | `config.test` 46 · `emergency.test` 147 · `instance-lock.test` 133 · `policy.test` 76 · `budget-ledger.test` 71 |

---

## 4. Entry points, hosts, artifacts

1. **CLI — `src/index.ts` (933 lines, the only `main`)**
   Flag dispatch at `src/index.ts:137-179`: `--bridge`, `--remote`, `--ui`, `--doctor`, `--ingest`, `--resume`, `--goal`. Everything else is a one-shot prompt or the interactive REPL (`src/index.ts:762-768`). SEA builds shift `argv` by one (`isSea`, line 129-137).

2. **Web UI host — `src/ui/web/main.ts` → `server.ts`**
   `runWebUi()` (`ui/web/main.ts:29`) starts `startWebUi()`; `server.ts` (2,409 lines) is a plain `node:http` server with **40 distinct `/api/*` routes** (`/api/ask`, `/api/approve`, `/api/tool`, `/api/tools`, `/api/sessions*`, `/api/keys*`, `/api/routes`, `/api/probe`, `/api/telegram*`, `/api/upload`, `/api/emergency-*`, …). Markup/CSS/JS are template strings in `ui/web/assets.ts` ("zero external assets, so it survives Node SEA .exe packaging", `assets.ts:1-4`). Bookmarklet ingestion is its own module (`POST /api/bookmarklet`, `ui/web/bookmarklet.ts`). Unlike the bridge, the UI is human-in-the-loop: approvals are Allow/Deny dialogs.

3. **Desktop shell — `desktop/tauri/`**
   Rust/Tauri v2 app (`src/main.rs`, 48 KB) that spawns the JS core: `node core/blackrose.mjs --ui <port>` (`desktop/tauri/src/main.rs:4`), waits on `/api/health` (`:824`), kills stale cores first (`:30`). Ships its own `node/node.exe` (93 MB) and a splash window `ui/index.html` (5.8 KB). `tauri.conf.json`: product `BlackRose`, version `0.10.2`, NSIS bundle, updater artifacts. No application logic in Rust beyond lifecycle/IPC.

4. **`dist/` vs `dist-build/` (both gitignored)**
   - `dist-build/` = `tsc` emit of the whole `src/` tree, one `.js` per module + mirrored subdirs. Intermediate only, input to the bundler.
   - `dist/` = release artifacts: `blackrose.mjs` (1,750,732 B, single-file bundle of all modules), `BlackRose.cmd` launcher, plus a few curriculum `.txt` fixtures. **No `BlackRose.exe` present** (build artifact not committed/present).
   - `scripts/build-exe.ts` pipeline (documented at `build-exe.ts:5-12`): `tsc` → custom single-file bundler → Node SEA → `dist/BlackRose.exe`.
   - `scripts/build-desktop.ts` stages `dist/blackrose.mjs` → `desktop/tauri/core/`, copies the node runtime → `desktop/tauri/node/`, generates `icons/icon.ico` from `src/ui/ico.ts`, validates the toolchain, then runs `npx tauri build` (NSIS).

---

## 5. Tool surface — 161 tools

`buildTools()` (`src/tools/index.ts:124`) returns a flat array of **161 `ToolDef`s**. Contract: `src/core/tools.ts:50-61` (`name`, `description`, `input_schema`, optional `requiresApproval`, `run`). Notable design fact stated in-code: `buildTool`'s default is *no approval*, and the comment records that "98 of 157 built-ins inherit it" (`core/tools.ts:63-78`) — so every state-changing tool must declare its own gate; `policy_*` can force one externally.

| Family | n | Tool names |
|---|---|---|
| Filesystem | 4 | `read_file` `write_file` `edit_file` `list_dir` |
| Undo | 1 | `undo` |
| Self-improvement | 5 | `propose_change` `improve_tool` `improve_status` `apply_change` `revert_change` |
| Shell / jobs / install | 5 | `run_command` `job_list` `job_output` `job_kill` `install` |
| Git (native) | 6 | `git_status` `git_log` `git_diff` `git_commit` `git_branch` `git_push` |
| Code review | 2 | `review_diff` `review_pr` |
| Secrets vault | 5 | `secret_set` `secret_get` `secret_list` `secret_delete` `secret_rotate` |
| Portable state | 2 | `ai_export` `ai_import` |
| One-AI-many-bodies | 6 | `robot_list` `robot_attach` `robot_detach` `state_push` `state_pull` `identity_restore` |
| Audit ledger | 2 | `audit_query` `log_append` |
| Policy ACL | 2 | `policy_set` `policy_status` |
| Timeline | 2 | `timeline_view` `session_log` |
| Image gen | 1 | `image_generate` |
| Custom tools | 3 | `tool_define` `tool_list` `tool_remove` |
| Web | 2 | `web_fetch` `web_search` |
| Memory | 3 | `memory_save` `memory_search` `memory_list` |
| Knowledge / learning | 17 | `learn_file` `learn_folder` `learn_pdf` `learn_docx` `learn_xlsx` `learn_pptx` `learn_epub` `learn_transcript` `learn_url` `knowledge_search` `knowledge_list` `knowledge_get` `knowledge_verify` `knowledge_forget` `knowledge_dedup` `knowledge_ingest` `knowledge_eval` |
| Office write | 5 | `doc_generate` `pptx_create` `xlsx_write` `xlsx_update` `xlsx_pivot` |
| Repo indexing | 3 | `repo_index` `repo_map` `repo_semantic_search` |
| Project memory | 2 | `project_note` `project_read` |
| Knowledge graph | 2 | `knowledge_graph` `graph_search` |
| Mastery | 5 | `mastery_start` `mastery_review` `mastery_status` `mastery_quiz` `mastery_gaps` |
| Experiment lab | 6 | `experiment_start` `experiment_run` `experiment_measure` `experiment_analyze` `experiment_stop` `experiment_status` |
| Scheduling | 3 | `schedule_task` `schedule_list` `schedule_remove` |
| Desktop / GUI | 3 | `screenshot` `read_image` `gui_action` |
| Voice | 2 | `say` `listen` |
| STT | 1 | `transcribe_audio` |
| Video | 3 | `watch_video` `video_generate` `video_slideshow` |
| Learning inbox | 2 | `inbox_scan` `inbox_review` |
| Instagram | 2 | `instagram_scrape` `instagram_learn` |
| Telegram | 2 | `telegram_send` `telegram` |
| OCR | 1 | `ocr_read` |
| Skills | 5 | `skill_save` `skill_list` `skill_run` `skill_versions` `skill_rollback` |
| Workflow | 3 | `workflow_create` `workflow_list` `workflow_run` |
| Macro record | 1 | `macro_record` |
| Sub-agent | 1 | `spawn_agent` |
| Teams | 7 | `team_create` `team_spawn` `team_invite` `team_task` `team_run` `team_list` `team_delete` |
| Goals / decisions | 8 | `goal_add` `goal_update` `goal_list` `goal_focus` `goal_remove` `decision_record` `decision_list` `decision_search` |
| Courses | 4 | `learn_curriculum` `learn_course_start` `learn_topic` `learn_course_status` |
| MCP | 6 | `mcp_connect` `mcp_disconnect` `mcp_list_servers` `mcp_list_tools` `mcp_call_tool` `mcp_search_tools` |
| Plugins | 4 | `plugin_load` `plugin_list` `plugin_remove` `plugin_reload` |
| Identity | 2 | `identity_set` `identity_get` |
| Mini-AI builder | 2 | `mini_build` `mini_list` |
| Notifications | 1 | `notify` |
| Budget | 2 | `budget_status` `budget_set` |
| Diagnostics | 1 | `doctor` |
| Emergency | 1 | `emergency_stop` |
| Local models | 3 | `lm_list` `lm_setup` `lm_switch` |

Registry order is deliberate, not alphabetical: working tools first; brain/identity/MCP/plugin tools last "so they sit last in the tool list" (`tools/index.ts` comments before `goalAddTool`).

---

## 6. Test layout

- **46 `*.test.ts` files, 9,105 lines total** (plus `smoke.ts`, 5,210 lines, outside `*.test.ts`).
- `npm test` = `node src/smoke.ts && node --test` with **43** explicit file arguments (`package.json:13`). Smoke runs first and must pass before any `node --test` file runs.
- Largest suites: `smoke.ts` 5,210 · `regression.test.ts` 1,923 · `audit-fixes.test.ts` 605 · `parser-hostile.test.ts` 320 · `tools/kb-ingest.test.ts` 297 · `tools/robots.test.ts` 276 · `bridge/aki.test.ts` 275 · `tools/telegram.helpers.test.ts` 257 · `tools/aistate.test.ts` 247 · `llm/adapters.test.ts` 235 · `tools/telegram.test.ts` 424 · `tools/office.test.ts` 196 · `tools/video.test.ts` 205 · `audit-sweep2.test.ts` 204.
- **Present but NOT wired into `npm test`:** `src/tools/policy.test.ts` (133), `src/tools/repo.test.ts` (68), `src/tools/kb-ingest.test.ts` (297) — 498 lines of tests that CI-by-script never runs. `src/policy.test.ts` (76) *is* wired, so the omission is not "policy has no tests".
- Coverage shape: 1 test for `llm/`, `mcp/`, `bridge/`, `session/`, `memory/vectors`, `core/{atomicFile,undo-gc,executive}`, and 24 under `tools/`.

---

## 7. `docs/` (13 files, ~500 KB)

| File | One line |
|---|---|
| `01-VISION.md` | Why BlackRose exists — product vision. |
| `02-CONSTITUTION.md` | "AI CONSTITUTION (draft v0.1)" — behavioral rules the agent is held to. |
| `03-ARCHITECTURE.md` | Layered ASCII diagram + "Phase 1–7 code map" of `src/` (**stale**, see §8). |
| `04-ROADMAP.md` | 36 KB phase roadmap. |
| `05-MODEL-INDEPENDENCE.md` | Provider-agnosticism notes (6.8 KB). |
| `06-TECH-GOD-CURRICULUM.txt` | Raw curriculum prompt/list (33 KB) fed to the learning features. |
| `07-BACKUP.md` | "moving your AI to another machine" — `.aistate` backup. |
| `07-BUILD-CHECKLIST.md` | 112 KB master build/status checklist; its row numbers are cited throughout code comments ("row 89", "B19"). |
| `08-SESSION-HANDOFF.md` | 57 KB session handoff, subtitled "read this FIRST". |
| `09-BOOKMARKLET.md` | The B10 browser bookmarklet. |
| `10-AGENT-INGEST.md` | AKI — agent knowledge ingestion. |
| `BLACKROSE_AI_OS_PROJECT_INSTRUCTIONS.txt` | 20 KB master project instructions (items cited as §41, item 51). |
| `BLACKROSE_CHECKPOINT.txt` | 248 KB running session log; newest block dated 2026-10-26, supersedes earlier tiers. |

---

## 8. Conflicts, caveats, unclear items

1. **`docs/03-ARCHITECTURE.md` is stale vs. code.** It advertises "202-check smoke test" and "51 regression tests", and its code map omits `core/{teams,workflow,plugins,policy,budget,undo}.ts`, `tools/{teams,knowledge,telegram,inbox,robots}.ts`, `state/`, `skills/`. Treat it as intent/history, not current structure. Code wins; this map is from code.
2. **Desktop bundle is stale.** `desktop/tauri/core/blackrose.mjs` = 1,729,792 B @ 26 Oct 11:52 vs `dist/blackrose.mjs` = 1,750,732 B @ 26 Oct 18:38. The staged copy predates the current bundle.
3. **Unverified:** whether `dist/blackrose.mjs` matches the working tree — checking would require running the build, which is out of scope.
4. **External binaries not declared in `package.json`** (shelled out to at runtime): `yt-dlp` (`tools/video.ts:20-45`, auto-downloaded to `~/.blackrose/bin/`), ffmpeg (video slideshow), PowerShell/WinRT (OCR, toast, SAPI TTS), `winget`/`npm`/`pnpm`/`pip` (`install` tool). "Zero dependency" holds for npm packages only.
5. **Unclear:** why `tools/policy.test.ts`, `tools/repo.test.ts`, `tools/kb-ingest.test.ts` are excluded from `npm test` — no comment states a reason.
6. `data/` and `validation/` at repo root are gitignored scratch dirs (knowledge-graph runtime state; release-audit output), not source.
7. `desktop/tauri/target/` holds local Rust build output (debug + release); not part of the source map.
