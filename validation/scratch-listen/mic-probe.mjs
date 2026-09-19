// Mic-path probe for the local push-to-talk tool: opens the DEFAULT audio
// input for a few seconds and reports whatever the local dictation engine
// hears. Reported honestly — ambient silence is a valid (non-error) outcome.
import { buildTools } from '../../cline/blackrose/src/tools/index.ts'

const listen = buildTools().find((t) => t.name === 'listen')
if (!listen) throw new Error('listen tool is not registered')
console.log('opening the default microphone for 5s — speak now if you want a transcript…')
const res = await listen.run({ seconds: 5 }, { cwd: process.cwd(), dataDir: process.cwd() })
console.log('\nisError=%s\n%s', res.isError === true, res.content)
console.log(res.isError === true ? 'MIC-PATH FAIL (error)' : 'MIC-PATH OK (engine ran; silence is fine)')