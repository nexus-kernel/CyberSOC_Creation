// The two HTML editions New-EbrSecurityReport.ps1 writes from the offline fixture: the client edition carries no
// presenter material and no identifiers anywhere in the file, and its client-facing results equal the internal
// edition's. Generation runs the real builder, so PowerShell 7 (pwsh) must be on PATH.
const { test } = require('node:test')
const assert = require('node:assert/strict')
const fs = require('node:fs')
const os = require('node:os')
const path = require('node:path')
const vm = require('node:vm')
const { execFileSync } = require('node:child_process')
const { build } = require('../report/report-model.js')
const { buildStory } = require('../report/report-story.js')

const root = path.join(__dirname, '..')
const GUID = /(?<![0-9a-f])[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?![0-9a-f])/gi

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
  return { internal: read(files[0]), client: read(files[1]), pack }
}
// Runs the scripts the file itself carries, after the data element, against a minimal document.
function read(file) {
  const html = fs.readFileSync(file, 'utf8')
  const json = html.match(/<script id="report-data" type="application\/json">([\s\S]*?)<\/script>/)[1]
  const data = JSON.parse(json)
  const nodes = {}
  const document = { body: { dataset: {} }, querySelectorAll: () => [], getElementById: id => nodes[id] || (nodes[id] = { id, textContent: id === 'report-data' ? json : '', addEventListener() {} }) }
  const context = vm.createContext({ document, window: {} })
  for (const [, code] of html.matchAll(/<script>([\s\S]*?)<\/script>/g)) vm.runInContext(code, context)
  return { html, json, data, report: nodes.report.innerHTML, review: nodes.review?.innerHTML ?? null }
}
// Placeholders for identifiers read the same in both editions once GUIDs and [id N] or [workspace N] are folded.
const fold = value => JSON.stringify(value).replace(GUID, '[id]').replace(/\[(id|workspace) \d+\]/g, '[id]')
const editions = generate()

test('the client edition carries no presenter notes, toggle, aside or presenter-only data', () => {
  const { internal, client } = editions
  const m = build(internal.data)
  assert.ok(m.presenter.length >= 5 && m.review.length >= 5 && m.timingRationale.length, 'the fixture raises presenter notes, review notes and a timing rationale')
  // The internal edition keeps the presenter notes as today.
  assert.match(internal.html, /<button id="review-toggle"[^>]*>Presenter notes<\/button>/)
  assert.match(internal.html, /<aside id="review" hidden/)
  for (const h of ['Prepared answers', 'Response timing cohort', 'Evidence review', 'Collection register']) assert.ok(internal.review.includes(`<h3>${h}</h3>`), h)
  // The client file holds none of it, in the markup, the scripts or the data.
  assert.ok(!client.html.includes('Presenter notes'), 'no Presenter notes string anywhere in the file')
  assert.ok(!/review-toggle|id="review"|Prepare the conversation|Collection register|Response timing cohort/.test(client.html))
  assert.equal(client.review, null, 'no script fills a review aside')
  const page = client.report
  for (const n of [...m.presenter, ...m.review]) assert.ok(!page.includes(n.text), `client page shows: ${n.title}`)
  for (const r of m.timingRationale) assert.ok(!page.includes(r.status), `client page shows the timing rationale: ${r.status}`)
  // Only the presenter notes read the evidence file notes, the manifest row counts and the context TenantId.
  assert.deepEqual(client.data.issues, [])
  assert.ok(client.data.manifest.length && client.data.manifest.every(r => !('Rows' in r)))
  assert.ok(!('TenantId' in client.data.context))
  for (const key of ['Subscriptions', 'AccessTenant', 'Warnings', 'GraphApi', 'RecentStart']) assert.ok(!(key in client.data.parameters), key)
  assert.equal(client.data.parameters.DefenderApi, 'Not available', 'the Advanced Hunting failure reason stays in the internal edition')
})

test('the client edition holds no GUID or workspace resource ID anywhere in the written file, embedded data included', () => {
  const { internal, client } = editions
  const ids = new Set(internal.json.match(GUID))
  assert.ok(ids.size >= 5, 'the fixture embeds subscription, workspace, tenant and reference GUIDs in the internal edition')
  assert.deepEqual(client.html.match(GUID), null)
  for (const s of ['/subscriptions/', 'rg-synthetic-private', 'rg-synthetic-sentinel', 'Microsoft.OperationalInsights']) assert.ok(!client.html.includes(s), s)
  // Subscription IDs become their distinct count, and each workspace keeps its name and retention only.
  assert.equal(client.data.parameters.SubscriptionCount, 2)
  assert.deepEqual(client.data.parameters.Workspaces, [
    { Name: 'DefaultWorkspace-[id 1]-EUS', RetentionDays: 90, CustomerId: '[workspace 1]' },
    { Name: 'synthetic-workspace', RetentionDays: 365, CustomerId: '[workspace 2]' }])
  assert.deepEqual(client.data.results['P0.1-BY-WORKSPACE'].map(r => [r.Workspace, r.WorkspaceId]), [['DefaultWorkspace-[id 1]-EUS', '[workspace 1]'], ['synthetic-workspace', '[workspace 2]']])
  // Evidence IDs and read dates stay in the source lines.
  assert.match(client.report, /DR\.9\. Read Oct 8, 2026\./)
  assert.match(client.report, /POS\.1\. Read Oct 8, 2026\./)
})

test("the client edition's client-facing results equal the internal edition's on the offline fixture", () => {
  const { internal, client } = editions
  const mi = build(internal.data), mc = build(client.data)
  // The model paths that join on identifiers still pair the same rows: the subscription count, the per-workspace
  // reach (one of two workspaces holds no alert records), analytics rules per workspace and the dispositions.
  assert.equal(mc.subscriptions, 2)
  assert.equal(mc.subscriptions, mi.subscriptions)
  assert.deepEqual(mc.workspaces.map(w => [w.Name, w.RetentionDays]).length, 2)
  assert.ok(mi.presenter.some(n => n.title === 'Workspace coverage' && n.text.startsWith('1 workspace holds')), 'P0.1-BY-WORKSPACE pairs the reach rows by workspace ID')
  assert.deepEqual(mc.presenter.map(n => n.title), mi.presenter.map(n => n.title))
  const rules = mi.controls.find(c => c.id === 'DR.9')
  assert.equal(rules.mark, 'N', 'one workspace has no enabled analytics rule')
  assert.ok(mi.controls.find(c => c.id === 'DR.10').pct !== null)
  // Everything the client sees, model and story, folded for the identifier placeholders.
  const facing = ({ presenter, review, timingRationale, manifest, issues, coverage, workspaces, ...rest }) => ({ ...rest, workspaces: workspaces.map(w => [w.Name, w.RetentionDays]) })
  assert.equal(fold(facing(mc)), fold(facing(mi)))
  for (const key of ['headline', 'pillars', 'controls', 'tiers', 'priorities', 'cloudScore', 'response', 'alerts']) assert.ok(JSON.stringify(mi[key]).length > 10, `${key} is populated`)
  const si = buildStory(mi, internal.data), sc = buildStory(mc, client.data)
  assert.ok(si.kpis.length === 4 && si.asks.length > 0)
  assert.equal(fold(sc), fold(si))
  // The rendered pages match, apart from the identifier placeholders.
  assert.equal(fold(client.report), fold(internal.report))
})
