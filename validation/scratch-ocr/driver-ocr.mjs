// Live driver: exercises learn_pdf OCR fallback + knowledge_search + ocr_read
// against a synthesized scanned PDF (image-only, no text layer) and a PNG.
import { learnPdfTool, knowledgeSearchTool } from 'file:///C:/Users/pc/Desktop/BlackRose/cline/blackrose/src/tools/knowledge.ts'
import { ocrReadTool } from 'file:///C:/Users/pc/Desktop/BlackRose/cline/blackrose/src/tools/ocr.ts'

const base = 'C:/Users/pc/Desktop/BlackRose/validation/scratch-ocr'
const ctx = {
  cwd: base,
  dataDir: base + '/state',
  askApproval: async () => true,
  log: () => {},
}

const out = (name, res) => {
  console.log(`=== ${name} ===`)
  console.log((res.isError ? '[ERROR] ' : '[OK] ') + res.content.slice(0, 600))
}

const pdfRes = await learnPdfTool.run({ path: base + '/scanned2.pdf' }, ctx)
out('learn_pdf (scanned â†’ OCR fallback)', pdfRes)

const search = await knowledgeSearchTool.run({ query: 'BLACKROSE OCR PROBE' }, ctx)
out('knowledge_search over OCR text', search)

const imgRes = await ocrReadTool.run({ path: base + '/test-ocr.png' }, ctx)
out('ocr_read (image)', imgRes)

const pdfRead = await ocrReadTool.run({ path: base + '/scanned2.pdf' }, ctx)
out('ocr_read (scanned pdf)', pdfRead)

const ok =
  !pdfRes.isError && pdfRes.content.includes('via OCR') &&
  search.content.includes('BLACKROSE OCR PROBE') &&
  !imgRes.isError && imgRes.content.includes('BLACKROSE OCR PROBE') &&
  !pdfRead.isError && pdfRead.content.includes('Line two')
console.log(ok ? 'DRIVER_ALL_PASS' : 'DRIVER_FAILED')

