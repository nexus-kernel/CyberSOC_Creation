// Renders the pages of the client edition of the HTML report ahead of time, for New-CyberSocReport.ps1.
// Usage: node build-client-report.cjs <report data.json> <output.json>
// The report model and renderer run here against a minimal document, the way the HTML runs them in the browser, so
// the client edition carries the rendered pages only: no embedded data, no report model and none of the presenter
// note, evidence review or timing rationale text the model holds. The output is { title, html }.
'use strict'
const fs = require('node:fs')
const path = require('node:path')
const vm = require('node:vm')

const [dataFile, outFile] = process.argv.slice(2)
if (!dataFile || !outFile) { console.error('Usage: node build-client-report.cjs <report data.json> <output.json>'); process.exit(1) }
const json = fs.readFileSync(dataFile, 'utf8')
const nodes = {}
const node = id => nodes[id] || (nodes[id] = { id, textContent: id === 'report-data' ? json : '', innerHTML: '', value: '', addEventListener() {} })
const document = { title: '', body: { dataset: {} }, querySelectorAll: () => [], getElementById: node }
const context = vm.createContext({ document, window: {} })
for (const file of ['report-model.js', 'cybersoc-model.js', 'report-render.js']) vm.runInContext(fs.readFileSync(path.join(__dirname, file), 'utf8'), context, { filename: file })
if (!nodes.report || !nodes.report.innerHTML) { console.error('The report pages were not rendered.'); process.exit(1) }
fs.writeFileSync(outFile, JSON.stringify({ title: document.title, html: nodes.report.innerHTML }))
