import { startWebUi } from "file:///C:/Users/pc/Desktop/BlackRose/cline/blackrose/src/ui/web/server.ts"
import { buildTools } from "file:///C:/Users/pc/Desktop/BlackRose/cline/blackrose/src/tools/index.ts"
import { learnFileTool } from "file:///C:/Users/pc/Desktop/BlackRose/cline/blackrose/src/tools/knowledge.ts"
import fs from "node:fs"

const dataDir = "C:/Users/pc/Desktop/BlackRose/validation/scratch-inspector/state"
fs.rmSync(dataDir, { recursive: true, force: true })
fs.mkdirSync(dataDir, { recursive: true })
const ctx = { cwd: dataDir, dataDir, askApproval: async () => true, log: () => {} }

const doc = dataDir + "/notes.md"
fs.writeFileSync(doc, "Kestrel telemetry notes: the launch window closes at 04:20 UTC and the abort corridor is 12 degrees wide.")
await learnFileTool.run({ path: doc }, ctx)

const client = { name: "mock", model: "m", call: async () => ({ text: "" }) }
const ui = await startWebUi({ client, system: "t", tools: buildTools(), dataDir, cwd: dataDir, port: 0 })
const post = async (name, input = {}) => (await (await fetch(ui.url + "/api/tool", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ name, input }) })).json())
const cat = await (await fetch(ui.url + "/api/tools")).json()
console.log("catalogue:", cat.tools.length, "tools,", cat.tools.filter(t => t.readOnly).length, "viewable from the UI")
console.log("knowledge_list ->", (await post("knowledge_list")).content)
const s = await post("knowledge_search", { query: "launch window abort corridor" })
console.log("knowledge_search ->", (s.content || "").slice(0, 160))
const denied = await fetch(ui.url + "/api/tool", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ name: "run_command", input: { command: "echo pwned" } }) })
console.log("run_command -> HTTP", denied.status, JSON.stringify((await denied.json()).error).slice(0, 100))
const gui = await post("gui_action", { action: "click" })
console.log("gui_action -> ok:", gui.ok, JSON.stringify(gui.error).slice(0, 70))
await ui.close()