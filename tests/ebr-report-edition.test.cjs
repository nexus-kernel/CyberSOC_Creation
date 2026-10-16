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
// Any GUID-shaped run, also inside a longer hexadecimal run such as the a<GUID>f workspace name in the fixture.
const GUID = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi

function generate(contextFile = path.join(__dirname, 'fixtures', 'offline-context.json')) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ebr-edition-'))
  const pack = path.join(dir, 'pack')
  fs.cpSync(path.join(__dirname, 'fixtures', 'offline-pack'), pack, { recursive: true })
  let out
  try {
    out = execFileSync('pwsh', ['-NoProfile', '-NonInteractive', '-File', path.join(root, 'New-EbrSecurityReport.ps1'), '-EvidencePath', pack,
      '-ContextPath', contextFile, '-Depth', 'Detailed', '-SkipDeck'], { encoding: 'utf8' })
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
  // Results and fields that feed presenter notes only, or that no page reads, are left out.
  for (const id of ['P0.1', 'P0.1-BY-WORKSPACE', 'EW.1-EDR', 'DR.12', 'IA.14', 'OUT.7']) {
    assert.ok(id in internal.data.results, `the fixture embeds ${id} in the internal edition`)
    assert.ok(!(id in client.data.results), id)
  }
  assert.deepEqual(internal.data.results['DP.1-CONTAINERS'], [{ Accounts: 2, AccountsUnread: 1, Containers: 10, PrivateContainers: 8, ExposedContainers: 2, AccountsExposed: 1 }])
  assert.deepEqual(client.data.results['DP.1-CONTAINERS'], [{ Containers: 10, PrivateContainers: 8 }])
  assert.deepEqual(client.data.results['P0.1-XDRDUP'], [{ InMultipleWorkspaces: 0 }])
  assert.ok(internal.data.results['IA.1'][0].MfaSessionLinkedOnly === 7 && !('MfaSessionLinkedOnly' in client.data.results['IA.1'][0]))
  assert.ok(!('UsersAlwaysMfa' in client.data.results['IA.1'][0]), 'a field no page reads is left out')
  assert.ok(!/"(ExposedContainers|AccountsExposed|AccountsUnread|XdrIncidents|MfaSessionLinkedOnly|ExcludedIdentities|LatestRecord|EarliestRecord)"/.test(client.json))
  assert.ok(m.presenter.some(n => n.title === 'Blob containers readable anonymously') && m.review.some(n => n.title === 'Blob containers not read'))
  // Context records the model omits stay in the internal edition only, with their owners and references.
  for (const s of ['CHG-401', 'CHG-OLD-77', 'CHG-OLD-78', 'Synthetic private owner']) {
    assert.ok(internal.json.includes(s), s)
    assert.ok(!client.json.includes(s), s)
  }
  assert.ok(m.review.some(n => n.title === 'Action status needs review') && m.review.some(n => n.title === 'Delivery record needs review'))
  // Names, references and other text the fixture marks private never reach the client file.
  assert.ok(!/synthetic-private/i.test(client.html))
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
    { Name: 'law-a[id 2]f', RetentionDays: 365, CustomerId: '[workspace 2]' }])
  assert.ok(internal.html.includes('law-ae2d4c6b8-a0f1-4e3d-9c5b-7a9f1e3d5c7bf'), 'the internal edition keeps a GUID between hexadecimal characters')
  assert.ok(!/e2d4c6b8|a0f1-4e3d|7a9f1e3d5c7b/i.test(client.html), 'the client edition masks it')
  // The same GUID reads as the same placeholder in every field and case, so DR.9 still pairs its scopes with the workspaces.
  assert.deepEqual([...new Set(client.data.results['DR.9'].map(r => r.Scope))], ['All workspaces', 'DefaultWorkspace-[id 1]-EUS', 'LAW-A[id 2]F'])
  // Evidence IDs and read dates stay in the source lines.
  assert.match(client.report, /DR\.9\. Read Oct 8, 2026\./)
  assert.match(client.report, /POS\.1\. Read Oct 8, 2026\./)
})

test("the client edition's client-facing results equal the internal edition's on the offline fixture", () => {
  const { internal, client } = editions
  const mi = build(internal.data), mc = build(client.data)
  // The model paths that join on identifiers still pair the same rows: the subscription count, the workspaces,
  // analytics rules per workspace and the dispositions. The per-workspace reach feeds a presenter note only, so it
  // stays in the internal edition, where one of the two workspaces holds no alert records.
  assert.equal(mc.subscriptions, 2)
  assert.equal(mc.subscriptions, mi.subscriptions)
  assert.equal(mc.workspaces.length, 2)
  assert.ok(mi.presenter.some(n => n.title === 'Workspace coverage' && n.text.startsWith('1 workspace holds')), 'P0.1-BY-WORKSPACE pairs the reach rows by workspace ID')
  for (const c of [mi, mc]) assert.equal(c.controls.find(x => x.id === 'DR.9').mark, 'N', 'one workspace has no enabled analytics rule')
  const rules = mi.controls.find(c => c.id === 'DR.9')
  assert.equal(rules.mark, 'N')
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
test('the client edition keeps every context record the model accepts and leaves out those it omits', () => {
  // Borderline records: dates with a time part where the model reads only the day, a padded key, a Verified status
  // with its delivery, a second record for a key already used, and records the model omits for each reason it checks.
  const window = { WindowStart: '2026-07-01', WindowEnd: '2026-09-30' }
  const action = (Key, Status, extra = {}) => ({ Key, Status, Reference: `REF-${Key}-${Status}`, Reviewed: '2026-10-10T08:00:00Z', ...window, ...extra })
  const context = {
    ClientName: 'Synthetic validation only', TenantId: 'example-tenant', ServiceStartDate: '2026-11-01',
    Delivered: [
      { Title: 'Kept delivery', Outcome: 'Done.', Reference: 'REF-verified', CompletedDate: '2026-07-01' },
      { Title: 'Late delivery', Outcome: 'Done.', Reference: 'REF-late', CompletedDate: '2026-10-01' },
      { Title: 'Timed delivery', Outcome: 'Done.', Reference: 'REF-timed', CompletedDate: '2026-08-01T00:00:00Z' },
      { Title: ' ', Outcome: 'Done.', Reference: 'REF-blank', CompletedDate: '2026-08-01' }],
    Actions: [
      action(' critical ', 'Proposed'), action('critical', 'Approved'), action('methods', 'Verified', { Reference: 'REF-verified' }),
      action('backup', 'Verified', { Reference: 'REF-nodelivery' }), action('pim', 'InProgress', { TargetDate: '2026-12-01T00:00:00Z' }),
      action('segment', 'Scheduled'), action('windows', 'Scheduled', { TargetDate: 'soon' }), action('mdi', 'Done'),
      action('sharing', 'Approved', { Reviewed: '2026-10-01' }), action('detect', 'Approved'), action('idp', 'Approved', { WindowStart: '2026-04-01' }),
      action('phish', 'Approved', { Reference: '' }), action('allowlist', 'Approved', { Reviewed: 'yesterday' })],
    Impact: { Confirmed: 0, Reviewed: '2026-09-29', Reference: 'REF-impact', ...window },
    OpenAlertNote: { AwaitingClient: 12, InProgress: 8, Reviewed: '2026-10-10T09:00:00Z', Reference: 'REF-open', ...window },
    ResponseTargetMinutes: 60
  }
  const file = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'ebr-context-')), 'context.json')
  fs.writeFileSync(file, JSON.stringify(context))
  const { internal, client } = generate(file)
  const mi = build(internal.data), mc = build(client.data)
  const used = m => ({ service: m.service, delivered: m.delivered, actions: m.actions, impact: m.impact, openSplit: m.alerts?.openSplit ?? null })
  assert.deepEqual(used(mc), used(mi))
  assert.deepEqual(mi.actions.map(a => [a.key, a.status]), [['critical', 'Proposed'], ['methods', 'Verified'], ['pim', 'InProgress']])
  assert.ok(mi.alerts.openSplit && !mi.impact && !mi.service, 'the fixture exercises an accepted and an omitted dated record')
  // Every reference the model omitted, apart from the records only the evidence or another record can rule out, is
  // left out of the client file.
  for (const ref of ['REF-late', 'REF-timed', 'REF-blank', 'REF-segment-Scheduled', 'REF-windows-Scheduled', 'REF-mdi-Done', 'REF-sharing-Approved', 'REF-detect-Approved', 'REF-idp-Approved', 'REF-allowlist-Approved', 'REF-impact']) {
    assert.ok(internal.json.includes(ref), ref)
    assert.ok(!client.json.includes(ref), ref)
  }
  assert.equal(client.data.context.ServiceStartDate, null)
  assert.ok(!('TenantId' in client.data.context))
})
