// Live driver for watch_video: real yt-dlp download + real cloud STT.
// Run: node validation/scratch-video/watch-probe.mts
import fs from 'node:fs'
import { watchVideoTool } from 'file:///C:/Users/pc/Desktop/BlackRose/cline/blackrose/src/tools/video.ts'

const scratch = 'C:/Users/pc/Desktop/BlackRose/validation/scratch-video'
const dataDir = scratch + '/state'
fs.rmSync(scratch + '/work', { recursive: true, force: true })
fs.mkdirSync(scratch + '/work', { recursive: true })
fs.mkdirSync(dataDir, { recursive: true })
// the STT key comes from User-scope env (BLACKROSE_OPENAI1_API_KEY) — inherited here

const ctx = { cwd: scratch + '/work', dataDir, askApproval: async () => true, log: (l) => console.log('  log:', l) }

const r = await watchVideoTool.run(
  { url: 'https://scontent-icn2-1.cdninstagram.com/o1/v/t2/f2/m86/AQPPWYcC7ElLqi1AQMad5vY35XpsIztYjTi4z8VUIlwrKVfNYsa2AgjLOHkYgR3-hFJYx5ABj-YRS9rOKMxSXMPP-f04ZCvGtfOUAfw.mp4?_nc_cat=111&_nc_sid=5e9851&_nc_ht=scontent-icn2-1.cdninstagram.com&_nc_ohc=595_BZmIUUgQ7kNvwExk-ZY&efg=eyJ2ZW5jb2RlX3RhZyI6Inhwdl9wcm9ncmVzc2l2ZS5JTlNUQUdSQU0uQ0xJUFMuQzMuNzIwLmRhc2hfYmFzZWxpbmVfMV92MSIsInhwdl9hc3NldF9pZCI6MjgxNTc5NDAyNTQ1OTc2NCwiYXNzZXRfYWdlX2RheXMiOjM2LCJ2aV91c2VjYXNlX2lkIjoxMDA5OSwiZHVyYXRpb25fcyI6NjksInVybGdlbl9zb3VyY2UiOiJ3d3cifQ%3D%3D&ccb=17-1&vs=f5edff709691718e&_nc_vs=HBksFQIYUmlnX3hwdl9yZWVsc19wZXJtYW5lbnRfc3JfcHJvZC8xQTQyQjdFNjcwNUZDQkQwRDk0OTNBODQ2MDkzNDE5Rl92aWRlb19kYXNoaW5pdC5tcDQVAALIARIAFQIYUWlnX3hwdl9wbGFjZW1lbnRfcGVybWFuZW50X3YyLzE5NDZDQjE0NzMwNjY5NUEzMDc3Mzc4NTc3N0VEREE3X2F1ZGlvX2Rhc2hpbml0Lm1wNBUCAsgBEgAoABgAGwKIB3VzZV9vaWwBMRJwcm9ncmVzc2l2ZV9yZWNpcGUBMRUAACbowK-q5LyAChUCKAJDMywXQFFiHKwIMScYEmRhc2hfYmFzZWxpbmVfMV92MREAdf4HZeadAQA&_nc_gid=LldUJW6NVy62t7dkNv6KFg&_nc_ss=7a22e&_nc_zt=28&oh=00_AQPWF48fgSLMGHkMQ0X4lDmRvgcOqcqLBDdh0KijqrgS3w&oe=6ABBF7D0', save: true, ingest: true },
  ctx,
)
console.log('--- result (isError:', r.isError === true, ') ---')
console.log(String(r.content).slice(0, 600))
console.log('--- sidecars ---')
const ups = scratch + '/work/blackrose-uploads'
console.log(fs.existsSync(ups) ? fs.readdirSync(ups).join(', ') : '(none)')
console.log('--- knowledge ---')
const kdir = dataDir + '/knowledge'
console.log(fs.existsSync(kdir) ? fs.readdirSync(kdir).filter((f) => f.endsWith('.json')).join(', ') : '(none)')
