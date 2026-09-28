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
  { url: 'https://instagram.fslw2-1.fna.fbcdn.net/o1/v/t2/f2/m86/AQOIpYLsxQFmkta2AtnfBE_lgvlL_fR4ADvSQ-_Un3g3gpG1Wlsp1epP691CL8blqqVOurgfdSYOtOaT6YdF06ZyKx4nMpjtk9FD7lc.mp4?_nc_cat=100&_nc_oc=AdppH0PkxikL-CUfwZfrZJCnqPUtznMXyczUKFlBx6Aq-XUogMb5fJpDV5pOV6IfxWg&_nc_sid=5e9851&_nc_ht=instagram.fslw2-1.fna.fbcdn.net&_nc_ohc=9FaQSQIaELYQ7kNvwHuJxOo&efg=eyJ2ZW5jb2RlX3RhZyI6Inhwdl9wcm9ncmVzc2l2ZS5JTlNUQUdSQU0uQ0xJUFMuQzMuNzIwLmRhc2hfYmFzZWxpbmVfMV92MSIsInhwdl9hc3NldF9pZCI6MjI5NzU4NDM5NDExMzA5MiwiYXNzZXRfYWdlX2RheXMiOjc2LCJ2aV91c2VjYXNlX2lkIjoxMDA5OSwiZHVyYXRpb25fcyI6NzgsInVybGdlbl9zb3VyY2UiOiJ3d3cifQ%3D%3D&ccb=17-1&vs=b6608e4e8c84b62d&_nc_vs=HBksFQIYUmlnX3hwdl9yZWVsc19wZXJtYW5lbnRfc3JfcHJvZC81QzQ1NEI4QjUwRjgyOEQ2NjgyMEM0MjlEMDI1MzQ5Nl92aWRlb19kYXNoaW5pdC5tcDQVAALIARIAFQIYUWlnX3hwdl9wbGFjZW1lbnRfcGVybWFuZW50X3YyL0VENEQ4MEFDOTNDNTkyQzMyQzI2NEUxREQxMkIwNEE3X2F1ZGlvX2Rhc2hpbml0Lm1wNBUCAsgBEgAoABgAGwKIB3VzZV9vaWwBMRJwcm9ncmVzc2l2ZV9yZWNpcGUBMRUAACaIwbjagemUCBUCKAJDMywXQFOGZmZmZmYYEmRhc2hfYmFzZWxpbmVfMV92MREAdf4HZeadAQA&_nc_gid=_-QEgb9D7TGKoksPVBsGvQ&_nc_ss=7a22e&_nc_map=urlgen_bucketless&_nc_zt=28&oh=00_AQPaiE2ksiwma3E8WyhiJGNxp-fr_1XTsru4H8NW-KCsBw&oe=6ABBE0E5', save: true, ingest: true },
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
