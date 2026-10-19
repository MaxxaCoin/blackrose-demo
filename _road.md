> **2026-10-15 (approval popup + custom-tools panel verification).** This session
> confirmed the **in-app approval popup is present end-to-end** — it was NOT missing.
> `server.ts` routes a tool's `askApproval` to an SSE `{type:'approval',…}` event
> (server.ts:290–300) and resolves it via `POST /api/approve` (server.ts:1208,
> `pendingApprovals` map: 122), and the UI's event loop dispatches that event to
> `handleApproval` (assets.ts:17714 in the served JS / `function handleApproval`
> at assets.ts:3641), which shows the Allow/Deny overlay. The **desktop shell**
> navigates the webview from the splash to the live UI
> (`desktop/tauri/src/main.rs:714` `location.replace('http://127.0.0.1:{port}/')`),
> so the popup appears there too. Doing `Get-Process` via chat typing consent is NOT
> enough — you must click **Allow** in the popup or enable **Trust** mode. No code
> change was needed. Also verified the handoff's next item: the UI
> `/custom_tools` panel is wired live (`assets.ts:2547` `btn-custom-tools`; server
> endpoints `/api/custom_tools` GET/POST + `/remove` at `server.ts:1340/1364/1397`).

**Phase 2 — Tier 4 "deferred vision" (only after Phase 1 — now open)**
| Order | Item | Gate |
|---|---|---|
| ~~9~~ | **B18 Autonomous Experiment Lab** — **DONE** (see above) | B12; blast radius needs B2 ✅ |
| 10 | **B23 One AI → Many Bodies** | 2nd device + B9 ✅ |
| 11 | **B24 Android companion** | hardware + B9 ✅ |
| ~~12~~ | **B22 Mini-AI / clone builder** — **DONE 2026-10-19** (`mini_build`/`mini_list` in `src/tools/mini.ts` + `exportStateSubset` in `src/state/aistate.ts`; capability packages only — private state unselectable; artifacts re-import via `ai_import`) | `.aistate` stable ✅ |
| 13 | **B19 Controlled self-improvement** | last — B2+B12+permissions |
| 14 | **B20 AI Software Factory** | large, unclear payoff |
| 15 | **B21 3D Website Factory** | narrow, high effort |

Recommended next: **B23 One AI → Many Bodies** (2nd device + B9 ✅ — B18 now done; B23 is the last item with a live gate).
## PENDING — full backlog (not built), priority order

Sourced from goal.txt capability objectives + build checklist + recommended additions.
Priority: **P0** unblocks the most of the spec · **P1** high-value capability · **P2** nice-to-have · **P3** deferred.

| Pri | Item | Source | Function(s) to build | Gate | Notes |
|---|---|---|---|---|---|
| **P0** | **B23 One AI → Many Bodies** | goal.txt Computer/AI Continuity | `robot_list`, `robot_attach`, `robot_detach`, `state_push`, `state_pull`, `identity_restore` | 2nd device + B9 ✅ | ✅ **DONE 2026-10-17** — `src/tools/robots.ts` + B23 sync via bridge; see checklist row 74. |
| **P0** | **MCP support** (Ecosystem) | goal.txt Ecosystem → MCP | `mcp_connect`, `mcp_disconnect`, `mcp_list_servers`, `mcp_list_tools`, `mcp_call_tool`, `mcp_search_tools` | — | ✅ **DONE 2026-10-15** — six interactive `mcp_*` tools + `McpRegistry` in `src/mcp/client.ts` (live connect/disconnect/list/call/search + persistence); registered in `src/tools/index.ts`. Verified: typecheck pass, 87/87 regression pass, integration against fakeServer (`mcp__fake__echo`, `echo:hello world`). |
| **P0** | **Native `git` tool** | goal.txt Development → Git | `git_status`, `git_log`, `git_diff`, `git_commit`, `git_branch`, `git_push` | — | ✅ **DONE** — structured tools in `src/tools/git.ts` (+ `git.test.ts`); see checklist row 77. |
| **P1** | **Secrets vault** | goal.txt Security → Secrets | `secret_set`, `secret_get`, `secret_list`, `secret_delete`, `secret_rotate` | config.ts | ✅ **DONE** — `src/tools/secrets.ts` (+ `secrets.test.ts`) over the B1 vault; see checklist row 78. |
| **P1** | **Runtime custom tools** | goal.txt Ecosystem → Custom tools | `tool_define`, `tool_list`, `tool_remove` (schema+handler per tool, persisted) | MCP infra reuses | ✅ **DONE 2026-10-15** — `tool_define/list/remove` + `<dataDir>/custom-tools.json`; wired into CLI/bridge/UI, surfaced in Telegram + UI panel. |

| **P1** | **Controlled self-improvement** | goal.txt Intelligence = **B19** | `improve_tool`, `propose_change`, `apply_change`, `revert_change` | B2+B12+permissions | Agent edits its own tools in a sandbox, tests, then flags. **Last** build per checklist. |
| **P1** | **Full export / import** | goal.txt AI Continuity | `ai_export`, `ai_import` (single artifact: state+memory+knowledge+skills+history) | — | ✅ **DONE 2026-10-17** — `src/tools/aistate.ts` over the `.aistate` engine; see checklist row 81. |
| **P1** | **Encrypted state** | goal.txt AI Continuity | AES-GCM at-rest wrapper on `.aistate` + portable dirs | — | ✅ **DONE 2026-10-17** — closed with row 81; see checklist row 82. |
| **P2** | **Multi-agent teams** | goal.txt Agents | `team_create`, `team_invite`, `team_spawn`, `team_task`, `team_run` | — | Only single `spawn_agent`; build persistent coordinated teams. |
| **P2** | **AI life timeline** | goal.txt AI Continuity | `timeline_view`, `session_log` (append-only experience ledger) | — | Sits on `.aihistory` + experiment records; visual history. |
| **P2** | **Image generation** | goal.txt Creative | `image_generate` (API-based) | — | One tool; no local model (API-only policy). |
| **P2** | **Document and presentation creation** | goal.txt Creative | `doc_generate`, `pptx_create` (write side of learn_docx/learn_pptx) | — | Completes the Office story. |
| **P2** | **Office write automation** | goal.txt Creative | `xlsx_write`, `xlsx_update`, `xlsx_pivot` | — | Mirrors learn_xlsx (write side). |
| **P2** | **Codebase indexing** | goal.txt Learning | `repo_index`, `repo_map`, `repo_semantic_search` | — | Persistent repo map beyond learn_folder. |
| **P2** | **Granular permissions** | goal.txt Security | `policy_set`, `policy_status` (per-tool / per-path ACL) | — | Extends current all-or-nothing approval gates. |
| **P2** | **Audit logs** | goal.txt Security | `audit_query` over structured action log (`log_append`) | — | User-visible transparency; feeds AI life timeline. |
| **P2** | **Plugins** | goal.txt Ecosystem | hot-load external tool packages (`PLUGIN_LOAD`) | MCP | Broader than MCP; make MCP a plugin type so the two converge. |
| **P3** | **AI Constitution / Core Identity** | goal.txt new concept | `identity_set`, `identity_get` + protected `ai_constitution` file | — | ✅ **DONE 2026-10-19** — model-agnostic identity layer; ties into export/import. See docs/07-BUILD-CHECKLIST.md row 92. |
| **P3** | **Video creation/editing** | goal.txt Creative | `video_generate`, `video_clip` | — | Only `watch_video` (read) exists; creation is heavier. |
| **P3** | **Native code review** | goal.txt Development | `review_diff`, `review_pr` (reuse graph/mastery) | — | ✅ **DONE 2026-10-19** — structured offline diff/branch review in `src/tools/review.ts` + pure analyzer `src/core/review.ts`; B3 redaction reused so secrets are flagged but never echoed; knowledge-graph cross-reference grounds findings in what the agent learned. See docs/07-BUILD-CHECKLIST.md row 94. |
| **P3** | **Deployment orchestration** | goal.txt Development | `deploy_config`, `deploy_run` (CI-like pipeline) | B20 | Fold into AI Software Factory if built; else standalone. |
| **P3** | **Android companion** | goal.txt Computer = **B24** | `android_scrape`, adb-based control | hardware + B9 | Hardware-gated. |

> Sequencing note: P3 items depend mostly on P0/P1 groundwork (export/import, MCP, secrets) —
> build top-down so each tier unblocks the next. `B24, B22, B19, B20, B21` remain the
> phased tail in the Phase-2 table above.
---

## DECISION 2026-09-29 — API-ONLY. Ollama is being removed.

**BlackRose will run on API providers only.** `src/llm/ollama.ts` is removed, the
`ollama` provider/route is deleted, and no local model is supported or documented.

Rationale: the cloud routes are the ones actually in use. The configured chain is
`openai2,gemini,openai3,onemin,openai,openai1,openai4,openai5,ollama` — eight API
routes ahead of Ollama, which is not running and has not been running. Local
inference was a fallback that never fired.
