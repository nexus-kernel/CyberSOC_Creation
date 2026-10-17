// The two HTML editions New-EbrSecurityReport.ps1 writes from the offline fixture. The client edition carries the
// rendered pages and the toolbar script only, so the whole written file holds no embedded data, no report model, no
// presenter or evidence review text and no GUID, and its pages read the same as the internal edition's. Generation
// runs the real builder, so PowerShell 7 (pwsh) and Node must be on PATH.
const { test } = require('node:test')
const assert = require('node:assert/strict')
const fs = require('node:fs')
const os = require('node:os')
const path = require('node:path')
const vm = require('node:vm')
const { execFileSync } = require('node:child_process')
const { build } = require('../report/report-model.js')

const root = path.join(__dirname, '..')
// Any GUID-shaped run, also inside a longer hexadecimal run such as the a<GUID>f workspace name in the fixture.
const GUID = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi

function generate() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ebr-edition-'))
  const pack = path.join(dir, 'pack')
  fs.cpSync(path.join(__dirname, 'fixtures', 'offline-pack'), pack, { recursive: true })
  let out
  try {
    out = execFileSync('pwsh', ['-NoProfile', '-NonInteractive', '-File', path.join(root, 'New-EbrSecurityReport.ps1'), '-EvidencePath', pack,
      '-ContextPath', path.join(__dirname, 'fixtures', 'offline-context.json'), '-Depth', 'Detailed', '-SkipDeck'], { encoding: 'utf8' })
  } catch (e) {
    if (e.code === 'ENOENT') assert.fail('PowerShell 7 (pwsh) must be on PATH to generate the report editions')
    throw e
  }
  const files = out.trim().split(/\r?\n/).map(s => s.trim())
  assert.deepEqual(files.map(f => path.basename(f)), ['03-security-report.html', '03-security-report.client.html'])
  return { internal: internalEdition(files[0]), client: clientEdition(files[1]) }
}
// The internal edition runs its own embedded scripts against a minimal document.
function internalEdition(file) {
  const html = fs.readFileSync(file, 'utf8')
  const json = html.match(/<script id="report-data" type="application\/json">([\s\S]*?)<\/script>/)[1]
  const nodes = {}
  const document = { title: '', body: { dataset: {} }, querySelectorAll: () => [], getElementById: id => nodes[id] || (nodes[id] = { id, textContent: id === 'report-data' ? json : '', addEventListener() {} }) }
  const context = vm.createContext({ document, window: {} })
  for (const [, code] of html.matchAll(/<script>([\s\S]*?)<\/script>/g)) vm.runInContext(code, context)
  return { html, json, data: JSON.parse(json), report: nodes.report.innerHTML, review: nodes.review.innerHTML, title: document.title }
}
// The client edition is read as written: its pages sit inside the main element.
function clientEdition(file) {
  const html = fs.readFileSync(file, 'utf8')
  return { html, report: html.match(/<main id="report" tabindex="-1">([\s\S]*)<\/main>/)[1], title: html.match(/<title>([^<]*)<\/title>/)[1] }
}
// Placeholders for identifiers read the same in both editions once GUIDs and [id N] are folded.
const fold = text => text.replace(GUID, '[id]').replace(/\[id \d+\]/g, '[id]')
// The fixed wording of every presenter note and evidence review note in the report model, as source text: each run of
// six or more words between the code around it.
const noteWording = () => fs.readFileSync(path.join(root, 'report', 'report-model.js'), 'utf8').split('\n')
  .filter(l => /\b(presenter|note|omitted)\(/.test(l) && !/const (presenter|note|omitted)\b/.test(l))
  .flatMap(l => l.split(/\$\{[^}]*\}?|[`'"(){}?:]|\|\||&&/))
  .map(s => s.trim()).filter(s => s.split(/\s+/).length >= 6 && /^[A-Za-z]/.test(s))
const editions = generate()

test('the client edition carries the rendered pages and the toolbar script only, with no data, model or presenter material', () => {
  const { internal, client } = editions
  const m = build(internal.data)
  assert.ok(m.presenter.length >= 5 && m.review.length >= 5 && m.timingRationale.length, 'the fixture raises presenter notes, review notes and a timing rationale')
  // The internal edition keeps the presenter notes as today.
  assert.match(internal.html, /<button id="review-toggle"[^>]*>Presenter notes<\/button>/)
  assert.match(internal.html, /<aside id="review" hidden/)
  for (const h of ['Prepared answers', 'Response timing cohort', 'Evidence review', 'Collection register']) assert.ok(internal.review.includes(`<h3>${h}</h3>`), h)
  // The client file holds one script, the toolbar's, and no embedded data or report model.
  const scripts = [...client.html.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script>/g)]
  assert.equal(scripts.length, 1)
  assert.equal(scripts[0][1], fs.readFileSync(path.join(root, 'report', 'report-controls.js'), 'utf8'))
  assert.ok(!/report-data|application\/json|EbrReport|function build|presenter\(/.test(client.html))
  assert.ok(!client.html.includes('Presenter notes'), 'no Presenter notes string anywhere in the file')
  assert.ok(!/review-toggle|id="review"|Prepare the conversation|Collection register|Response timing cohort/.test(client.html))
  // No computed presenter, review or timing rationale text, and none of the fixed wording of those notes in the model.
  for (const n of [...m.presenter, ...m.review]) assert.ok(!client.html.includes(n.text), `client file holds: ${n.title}`)
  for (const r of m.timingRationale) assert.ok(!client.html.includes(r.status), `client file holds the timing rationale: ${r.status}`)
  const wording = noteWording()
  assert.ok(wording.length > 60, `${wording.length} fixed note phrases read from the model`)
  assert.ok(internal.html.includes('Say so if asked, or add portal counts'), 'the internal edition carries the model source')
  // A phrase the pages themselves print, such as the open alert split, is page copy rather than note wording.
  const notes = wording.filter(phrase => !internal.report.includes(phrase))
  assert.ok(notes.length > 60)
  for (const phrase of notes) assert.ok(!client.html.includes(phrase), `client file holds note wording: ${phrase}`)
  // Nothing the data holds for the presenter alone reaches the file: omitted context records, presenter-only counts
  // and the names the fixture marks private.
  for (const s of ['CHG-401', 'CHG-OLD-77', 'CHG-OLD-78', 'Synthetic private owner', 'synthetic-private', 'ExposedContainers', 'readable anonymously', 'example-tenant']) {
    assert.ok(internal.html.includes(s), `the fixture embeds ${s} in the internal edition`)
    assert.ok(!client.html.includes(s), s)
  }
})

// The offline fixture reads no Defender XDR alert in Sentinel (P0.1-XDRDUP XdrIncidents 0), so the client edition
// states the scope on the operations page, in words that are not the presenter note's (issue #22).
test('the client edition states the Defender XDR scope on the operations page', () => {
  const { internal, client } = editions
  const m = build(internal.data)
  assert.equal(m.xdrScope.state, 'excluded')
  assert.ok(m.presenter.some(n => n.title === 'Defender XDR scope'), 'the presenter note is raised as well')
  const howTo = client.report.match(/<h3>How to read this page<\/h3><p>([\s\S]*?)<\/p>/)[1]
  assert.ok(howTo.includes('detections are the alerts correlated into those tickets. Alerts investigated only in other platforms, including Microsoft Defender XDR, are not included. No Defender XDR alert was found in Sentinel in the year before collection. The SOC triages each alert'), howTo)
  assert.ok(!client.html.includes('Defender services'))
})
test('the client edition holds no GUID or workspace resource ID anywhere in the written file', () => {
  const { internal, client } = editions
  assert.ok(new Set(internal.json.match(GUID)).size >= 5, 'the fixture embeds subscription, workspace, tenant and reference GUIDs in the internal edition')
  assert.deepEqual(client.html.match(GUID), null)
  for (const s of ['/subscriptions/', 'rg-synthetic-private', 'rg-synthetic-sentinel', 'Microsoft.OperationalInsights', 'e2d4c6b8']) assert.ok(!client.html.includes(s), s)
  // GUIDs inside names become one placeholder each, also between hexadecimal characters.
  assert.ok(internal.report.includes('law-ae2d4c6b8-a0f1-4e3d-9c5b-7a9f1e3d5c7bf'), 'the internal page shows a GUID between hexadecimal characters')
  assert.match(client.report, /<td>law-a\[id \d+\]f<\/td>/)
  assert.match(client.report, /<td>DefaultWorkspace-\[id \d+\]-EUS<\/td>/)
  assert.match(client.report, /Reviewed impact determination Review \[id \d+\]/, 'a GUID in a context Reference is masked')
  // Evidence IDs and read dates stay in the source lines, and the subscription count stays in the scope line.
  assert.match(client.report, /DR\.9\. Read Oct 8, 2026\./)
  assert.match(client.report, /POS\.1\. Read Oct 8, 2026\./)
  assert.match(client.report, /2 subscriptions · 2 Sentinel workspaces/)
})

test("the client edition's pages equal the internal edition's on the offline fixture", () => {
  const { internal, client } = editions
  const m = build(internal.data)
  // The fixture reaches the model paths that join on identifiers and the context records it reads.
  assert.equal(m.controls.find(c => c.id === 'DR.9').mark, 'N', 'one workspace has no enabled analytics rule')
  assert.ok(m.presenter.some(n => n.title === 'Workspace coverage' && n.text.startsWith('1 workspace holds')))
  assert.ok(m.alerts.openSplit && m.impact && m.delivered.length === 1 && m.actions.length === 1)
  assert.equal(fold(client.report), fold(internal.report))
  assert.equal(client.title, internal.title)
  assert.match(client.html, /<option value="detailed" selected>/)
})
