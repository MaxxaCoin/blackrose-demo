import { readFileSync, writeFileSync } from 'node:fs'
writeFileSync(process.argv[3], Buffer.from(readFileSync(process.argv[2],'utf8').trim(),'base64').toString('utf8'))
const pt = Buffer.from(readFileSync(process.argv[4],'utf8').trim(),'base64').toString('utf8')
writeFileSync(process.argv[5], pt.split(/\r?\n/).map(l=>l.trim()).find(l=>l&&!l.startsWith('untrusted comment')))