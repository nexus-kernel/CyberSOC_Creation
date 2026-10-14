const { test } = require('node:test')
const assert = require('node:assert/strict')
const fs = require('node:fs')
const os = require('node:os')
const path = require('node:path')
const vm = require('node:vm')
const { execFileSync } = require('node:child_process')
const { build } = require('../report/report-model.js')
const { JSZip } = require('../report/deck-common.cjs')

// Exercise both real renderers: a monthly chart is evidence, not a positive-change badge.
for (const [name, values] of [['declining', [60, 55, 50]], ['flat', [50, 50, 50]], ['rising', [40, 45, 50]], ['one reading', [50]], ['no history', []]]) {
  test(`HTML and PowerPoint retain ${name} cloud history when sufficient`, async () => {
    const trend = values.map((Percent, i) => ({ Month: `2026-0${i + 7}-01`, Percent }))
    // Invalid readings must not manufacture sufficient history or reach either chart.
    trend.push({ Month: 'invalid', Percent: 65 }, { Month: '2026-10-01', Percent: 101 }, { Month: '2026-10-01', Percent: -1 }, { Month: '2026-10-01', Percent: null })
    const data = {
      depth: 'detailed', parameters: { ClientName: 'Trend fixture', PostureReadDate: '2026-10-08', Subscriptions: ['s1'], Workspaces: [] },
      manifest: ['POS.1', 'POS.7'].map(ResultId => ({ ResultId, Status: 'OK' })),
      results: { 'POS.1': [{ Current: 50, Max: 100, Subscriptions: 1 }], 'POS.7': trend.reverse() }
    }
    const m = build(data), expectedChart = values.length >= 2
    assert.deepEqual(m.cloudScore.trend.map(r => r.pct), values)
    if (name === 'declining') {
      assert.equal(m.cloudScore.delta, null)
      assert.match(m.presenter.find(n => n.title === 'Defender for Cloud score movement').text, /shows the monthly trend, including declines/)
    }
    const nodes = {}
    const document = {
      body: { dataset: {} }, querySelectorAll: () => [],
      getElementById: id => nodes[id] || (nodes[id] = { textContent: id === 'report-data' ? JSON.stringify(data) : '', addEventListener() {} })
    }
    vm.runInNewContext(fs.readFileSync(path.join(__dirname, '../report/report-render.js'), 'utf8'), { EbrReport: require('../report/report-model.js'), document, window: {} })
    assert.equal(nodes.report.innerHTML.includes('aria-label="Defender for Cloud score by month"'), expectedChart)
    assert.ok(nodes.report.innerHTML.includes('measurement model'))
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ebr-trend-'))
    try {
      const input = path.join(dir, 'data.json'), output = path.join(dir, 'deck.pptx')
      fs.writeFileSync(input, JSON.stringify(data))
      execFileSync(process.execPath, [path.join(__dirname, '../report/build-report-deck.cjs'), input, output])
      const zip = await JSZip.loadAsync(fs.readFileSync(output))
      const charts = await Promise.all(Object.keys(zip.files).filter(n => /^ppt\/charts\/chart\d+\.xml$/.test(n)).map(n => zip.file(n).async('string')))
      const lineCharts = charts.filter(c => c.includes('<c:lineChart>'))
      assert.equal(lineCharts.length, expectedChart ? 1 : 0)
      if (expectedChart) {
        const numeric = lineCharts[0].match(/<c:numCache>([\s\S]*?)<\/c:numCache>/)[1]
        assert.deepEqual([...numeric.matchAll(/<c:v>([^<]+)<\/c:v>/g)].map(m => Number(m[1])), values)
      }
    } finally { fs.rmSync(dir, { recursive: true, force: true }) }
  })
}
