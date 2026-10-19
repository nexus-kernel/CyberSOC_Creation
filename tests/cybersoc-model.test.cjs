// The CyberSOC monthly report model (report/cybersoc-model.js) and its pages. Synthetic packs only.
const { test } = require('node:test')
const assert = require('node:assert/strict')
const fs = require('node:fs')
const path = require('node:path')
const vm = require('node:vm')
const R = require('../report/report-model.js')
const C = require('../report/cybersoc-model.js')

function pack() {
  return {
    parameters: { ClientName: 'Example', ReportType: 'CyberSOC monthly', ReportMonth: '2026-09', TrendMonths: 3, WindowStart: '2026-07-01', WindowEnd: '2026-09-30', RecentStart: '2026-07-01', PostureReadDate: '2026-10-08', DefenderApi: 'available', TicketPattern: 'ZD', Subscriptions: ['s1'], Workspaces: [{ Name: 'w1', CustomerId: 'w1' }] },
    manifest: [], results: {}, context: null
  }
}
function put(p, id, rows, status = 'OK', extra = {}) {
  p.manifest = p.manifest.filter(m => m.ResultId !== id)
  p.manifest.push({ ResultId: id, Status: status, Rows: rows.length, ReadTimeUtc: '2026-10-08T10:00:00Z', ...extra })
  p.results[id] = rows
}
const months = ['2026-07-01', '2026-08-01', '2026-09-01']
function operations(p) {
  put(p, 'OUT.1', [{ Raised: 100, Closed: 90, Open: 10, TruePositive: 3, ClosedUnclassified: 0 }])
  put(p, 'OUT.2', [{ Scope: 'All', Incidents: 90, AutoClosed: 5, MedianCloseMin: 30, P90CloseMin: 55 }, { Scope: 'High', Incidents: 30, AutoClosed: 0, MedianCloseMin: 25, P90CloseMin: 50 }])
  put(p, 'OUT.3', months.map((Month, i) => ({ Month, Total: [30, 32, 38][i], High: [8, 10, 12][i], Medium: 10, Low: 12, Informational: 0, TruePositive: [1, 0, 2][i], FalsePositive: 1 })))
  put(p, 'OUT.2-MONTH', months.flatMap((Month, i) => [{ Month, Scope: 'High', Incidents: [9, 4, 11][i], AutoClosed: 0, MedianTriageMin: 3, MedianCloseMin: [28, 26, 18][i], P90CloseMin: [50, 55, 70][i] }, { Month, Scope: 'All', Incidents: 30, AutoClosed: 1, MedianTriageMin: 4, MedianCloseMin: 25, P90CloseMin: 58 }]))
  put(p, 'OUT.3-WEEK', [{ Week: '2026-07-01', Total: 7, High: 2, Medium: 2, Low: 3, TruePositive: 0 }, { Week: '2026-09-23', Total: 9, High: 3, Medium: 2, Low: 4, TruePositive: 1 }])
  put(p, 'OUT.9', [{ Month: '2026-09-01', Title: 'Multi-stage incident involving Execution', Alerts: 9, High: 5, TruePositive: 2 }, { Month: '2026-08-01', Title: 'Title withheld', Alerts: 3, High: 0, TruePositive: 0 }, { Month: '2026-09-01', Title: 'Suspicious sign-in activity', Alerts: 12, High: 3, TruePositive: 0 }])
}
function threats(p, { tables = ['SecurityAlert', 'SigninLogs', 'ThreatIntelIndicators', 'AADUserRiskEvents'] } = {}) {
  put(p, 'TI.0', tables.map(SourceTable => ({ SourceTable, Records: 100 })))
  put(p, 'TI.1', [{ Source: 'Feed A', Kind: 'IP address', Indicators: 100, Active: 90 }, { Source: 'Feed B', Kind: 'Domain', Indicators: 50, Active: 40 }])
  put(p, 'TI.2', [{ Month: '2026-08-01', Indicator: 'IP address', AlertSeverity: 'Medium', Detections: 4, Ticketed: 3 }, { Month: '2026-09-01', Indicator: 'Domain', AlertSeverity: 'High', Detections: 2, Ticketed: 2 }])
  put(p, 'TI.3', [{ Month: '2026-09-01', Tactic: 'Exfiltration', Alerts: 2, TruePositiveAlerts: 0, Detections: 2 }, { Month: '2026-07-01', Tactic: 'InitialAccess', Alerts: 10, TruePositiveAlerts: 1, Detections: 12 }, { Month: '2026-09-01', Tactic: 'InitialAccess', Alerts: 6, TruePositiveAlerts: 1, Detections: 6 }])
  put(p, 'TI.4', [{ Technique: 'T1078.004', Alerts: 5, TruePositiveAlerts: 1, Detections: 6 }, { Technique: 'T9999', Alerts: 1, TruePositiveAlerts: 0, Detections: 1 }, { Technique: 'not an id', Alerts: 9 }])
  put(p, 'TI.5', months.map((Month, i) => ({ Month, SignIns: 1000, FailedPassword: [10, 20, 30][i], TargetedUsers: 5, Lockouts: 1, BlockedByCa: 2, RiskySignIns: [1, 2, 3][i], RiskyUsers: 1, SuccessfulRisky: 0, RiskHidden: 0, SprayIps: [0, 1, 2][i], SprayDays: 1 })))
  put(p, 'TI.5-RISK', [{ Month: '2026-09-01', RiskEventType: 'unfamiliarFeatures', Detections: 4, Users: 3, High: 1 }, { Month: '2026-08-01', RiskEventType: 'someNewDetection', Detections: 1, Users: 1, High: 0 }])
  put(p, 'TI.6', [], 'EMPTY', { NoTable: true })
  put(p, 'TI.7', [{ Threat: 'Trojan:Win32/Example.A', Detections: 2, Devices: 1, Remediated: 2, WasExecuting: 0 }])
}
function runs(p) {
  put(p, 'VA.RUNS', [
    { RunDate: '2026-08-01', Status: 'Complete', Open: 6, Critical: 1, High: 2, Medium: 2, Low: 1, Vms: 4, Cves: 5, KevChecked: true, KevOpen: 1, KevVms: 1, KevAddedInReportMonth: 0, ExploitChecked: true, ExploitOpen: 2, NoVendorFix: 0, EosVms: 0, OwnerProvider: 4, OwnerClient: 2, OwnerUnknown: 0, Status_remediation_required: 6 },
    { RunDate: '2026-10-01', Status: 'Complete', Open: 7, Critical: 3, High: 2, Medium: 1, Low: 1, Vms: 4, Cves: 6, KevChecked: true, KevOpen: 4, KevVms: 2, KevAddedInReportMonth: 2, ExploitChecked: false, ExploitOpen: 4, NoVendorFix: 1, EosVms: 1, OwnerProvider: 2, OwnerClient: 5, OwnerUnknown: 0, Status_remediation_required: 3, Status_pending_client_action: 3, Status_pending_vendor_fix: 1 }])
  put(p, 'VA.CHANGE', [{ FromRun: '2026-08-01', ToRun: '2026-10-01', Compared: true, Reason: '', New: 3, NoLongerReported: 2, Persistent: 4, OpenEarlier: 6, OpenCurrent: 7, OpenNew: 3, OpenNoLonger: 2 }])
  put(p, 'VA.TOP', [{ Product: 'Log4j Core', Severity: 'Critical', Vms: 2, Findings: 2, Cves: 2, Kev: true, Exploit: true, MaxCvss: 10, FixStatus: 'available', Owner: 'CLIENT' }, { Product: 'libxml2', Severity: 'Medium', Vms: 1, Findings: 1, Cves: 1, Kev: false, Exploit: false, MaxCvss: 6.5, FixStatus: 'not_available', Owner: 'SHARED' }])
  put(p, 'VA.KEV', [{ Product: 'Log4j Core', Severity: 'Critical', Vms: 2, Findings: 2, KevDateAdded: '2026-09-10', AddedThisMonth: true }])
}
const full = () => { const p = pack(); operations(p); threats(p); runs(p); return p }
const both = p => { const m = R.build(p); return { m, cs: C.build(p, m) } }
// Every string the model hands to a page or slide.
const strings = value => typeof value === 'string' ? [value] : Array.isArray(value) ? value.flatMap(strings) : value && typeof value === 'object' ? Object.entries(value).filter(([k]) => !['presenter', 'review'].includes(k)).flatMap(([, v]) => strings(v)) : []

test('the report month is the month of the window end and the trend holds the three full months', () => {
  const { cs } = both(full())
  assert.deepEqual([cs.month.key, cs.month.label, cs.month.valid, cs.month.partial], ['2026-09', 'September 2026', true, false])
  assert.deepEqual(cs.months.map(x => [x.label, x.report]), [['Jul 2026', false], ['Aug 2026', false], ['Sep 2026', true]])
  assert.equal(cs.window.days, 92)
  const p = full(); p.parameters.WindowEnd = '2026-09-20'; p.parameters.ReportMonth = undefined
  const short = both(p).cs
  assert.equal(short.month.partial, true)
  assert.ok(short.presenter.some(n => n.title === 'Partial report month'))
})

test('monthly alerts, weekly bins and timing follow the alert gate, and a month under 5 closed alerts has no timing', () => {
  const { cs } = both(full())
  assert.deepEqual(cs.ops.monthly.map(x => [x.total, x.high, x.tp]), [[30, 8, 1], [32, 10, 0], [38, 12, 2]])
  assert.equal(cs.ops.weekly.length, 14, '92 days in 7-day bins from the window start')
  assert.deepEqual([cs.ops.weekly[0].total, cs.ops.weekly[1].total, cs.ops.weekly[12].total, cs.ops.weekly[13].days], [7, 0, 9, 1])
  assert.match(cs.ops.weeklyNote, /The last bin covers 1 day\./)
  assert.equal(cs.ops.timing[1].high.withheld, true, 'August has 4 closed high severity alerts')
  assert.equal(cs.ops.timing[2].high.belowFloor, true)
  assert.equal(cs.ops.timing[2].high.overHour, true)
  const august = cs.glance.rows.find(r => r.label === 'Median time to close, high severity')
  assert.deepEqual(august.values, ['28 min', 'Not available', '18 min'])
  assert.equal(august.change, '', 'no change is computed against a withheld month')
  // Duplicate alerts across workspaces withhold every alert figure, monthly ones included.
  const p = full(); p.parameters.Workspaces.push({ Name: 'w2', CustomerId: 'w2' }); put(p, 'P0.1-XDRDUP', [{ XdrIncidents: 5, InMultipleWorkspaces: 2 }])
  const dup = both(p).cs
  assert.deepEqual([dup.ops.monthly.length, dup.ops.weekly.length, dup.ops.timing.length, dup.ops.types.length], [0, 0, 0, 0])
  assert.ok(!dup.headline.some(t => /Alerts created/.test(t.label)))
})

test('alert types read as alerts, and withheld titles are counted, never named', () => {
  const { cs } = both(full())
  assert.deepEqual(cs.ops.types.map(t => t.title), ['Suspicious sign-in activity', 'Multi-stage alert involving Execution'])
  assert.equal(cs.ops.typesWithheld, 3)
  assert.ok(!strings(cs).some(t => /\bincidents?\b/i.test(t)), 'client copy says alerts')
})

test('the month at a glance shows the months side by side with a neutral change', () => {
  const { cs } = both(full())
  const row = label => cs.glance.rows.find(r => r.label === label)
  assert.deepEqual(row('Alerts created').values, ['30', '32', '38'])
  assert.equal(row('Alerts created').change, '6 more')
  assert.equal(row('Confirmed threats').change, '2 more')
  assert.equal(row('Password spraying sources').change, '1 more')
  assert.ok(!cs.glance.rows.some(r => /improv|worse|better|declin/i.test(r.change)))
  assert.equal(C.changeOf(20, 25, 'minutes'), '5 min shorter')
  assert.equal(C.changeOf(60, 58.04, 'points'), 'Up 2 points')
  assert.equal(C.changeOf(3, 3), 'No change')
})

test('threat intelligence never reads a zero from a table Sentinel does not hold', () => {
  const { cs } = both(full())
  assert.equal(cs.threat.email, undefined)
  assert.ok(cs.threat.unmeasured.some(u => u.id === 'TI.6' && /EmailEvents/.test(u.reason)))
  // Without TI.0 every table-dependent measure is not gathered, even when its own result is EMPTY.
  const p = full(); p.manifest = p.manifest.filter(r => r.ResultId !== 'TI.0'); put(p, 'TI.2', [], 'EMPTY')
  const none = both(p).cs
  for (const k of ['indicators', 'matches', 'identity', 'risk']) assert.equal(none.threat[k], undefined, k)
  assert.ok(!none.headline.some(t => /Threat intelligence matches/.test(t.label)))
  // A TI.0 without the indicator tables leaves the indicators unmeasured.
  const q = pack(); threats(q, { tables: ['SecurityAlert'] })
  assert.equal(both(q).cs.threat.indicators, undefined)
  // EMPTY matches with the alert table present is a real zero.
  const z = full(); put(z, 'TI.2', [], 'EMPTY')
  assert.equal(both(z).cs.threat.matches.total, 0)
  assert.ok(both(z).cs.summary.some(t => t === 'No threat intelligence indicator matched your telemetry this month.'))
})

test('threat intelligence aggregates by kill chain order, names techniques and risk types, and states its boundaries', () => {
  const { cs } = both(full())
  const t = cs.threat
  assert.deepEqual([t.indicators.total, t.indicators.active, t.indicators.feedCount], [150, 130, 2])
  assert.deepEqual([t.matches.total, t.matches.month, t.matches.ticketed], [6, 2, 5])
  assert.deepEqual(t.stages.rows.map(s => [s.label, s.alerts, s.month]), [['Initial access', 16, 6], ['Exfiltration', 2, 2]])
  assert.deepEqual(t.techniques.rows.map(x => x.label), ['Valid Accounts (T1078.004)', 'T9999'])
  assert.deepEqual(t.risk.rows.map(r => r.label), ['Unfamiliar sign-in properties', 'Some new detection'])
  assert.equal(t.identity.riskVisible, true)
  assert.ok(cs.summary.some(s => /most often initial access\. A tactic is a label recorded at detection, not an investigation finding\./.test(s)))
  assert.ok(!strings(cs).some(s => /\breached\b|compromise occurred|no impact/i.test(s)))
  assert.ok(cs.review.some(r => r.title === 'Threat intelligence boundaries'))
  // Risk levels hidden from the tenant leave the risky sign-in row out rather than reading zero.
  const p = full(); put(p, 'TI.5', months.map(Month => ({ Month, SignIns: 100, RiskHidden: 90, RiskySignIns: 0 })))
  const hidden = both(p).cs
  assert.equal(hidden.threat.identity.riskVisible, false)
  assert.ok(!hidden.glance.rows.some(r => r.label === 'Medium and high risk sign-ins'))
})

test('vulnerability management reads the assessment runs, with the KEV listing, the change and the owners', () => {
  const { cs } = both(full())
  const v = cs.vuln
  assert.equal(v.mode, 'runs')
  assert.deepEqual([v.latest.open, v.latest.kev, v.latest.kevThisMonth, v.latest.exploit], [7, 4, 2, null], 'public exploit is not checked in the latest run')
  assert.deepEqual([v.change.openNew, v.change.openGone, v.change.compared], [3, 2, true])
  assert.deepEqual(v.top.map(t => [t.product, t.fix, t.owner]), [['Log4j Core', 'Fix available', 'Your team'], ['libxml2', 'No vendor fix yet', 'Atmosera and your team']])
  assert.deepEqual(v.statuses.map(s => s.label), ['Remediation required', 'Pending client action', 'Pending vendor fix'])
  assert.ok(cs.review.some(r => r.title === 'Public exploit not checked'))
  const tile = cs.headline.find(t => t.label === 'Open critical and high vulnerability findings')
  assert.deepEqual([tile.value, tile.sub], ['5', '4 with a CISA KEV-listed CVE. Assessment of Oct 1, 2026'])
  const s = cs.summary.find(x => x.startsWith('The vulnerability assessment'))
  assert.match(s, /3 open findings are new and 2 are no longer open, pending validation\.$/)
  for (const x of [...cs.summary, ...cs.headline.map(t => `${t.label} ${t.sub}`)]) assert.ok(!/remediated|resolved/i.test(x), x)
})

test('without assessment runs the page reads the Defender current state, and with neither it says the review completes it', () => {
  const p = full()
  for (const id of ['VA.RUNS', 'VA.CHANGE', 'VA.TOP', 'VA.KEV']) { p.manifest = p.manifest.filter(r => r.ResultId !== id); delete p.results[id] }
  put(p, 'VA.1', [{ VulnerabilitySeverityLevel: 'Critical', Cves: 4, Devices: 3, Exposures: 9, ExploitableCves: 2 }, { VulnerabilitySeverityLevel: 'High', Cves: 18, Devices: 5, Exposures: 40, ExploitableCves: 5 }])
  put(p, 'VA.3', [{ Month: '2026-09-01', Cves: 9, Critical: 2, High: 4, ExploitableCves: 2 }])
  const d = both(p).cs
  assert.equal(d.vuln.mode, 'defender')
  assert.deepEqual([d.vuln.defender.cves, d.vuln.defender.exploitable, d.vuln.defender.published[2].cves, d.vuln.defender.published[0].cves], [22, 7, 9, 0])
  assert.equal(d.headline.find(t => /CVEs open/.test(t.label)).value, '22')
  assert.ok(d.review.some(r => r.title === 'Vulnerability management source'))
  p.manifest = p.manifest.filter(r => r.ResultId !== 'VA.1')
  const n = both(p).cs
  assert.equal(n.vuln.mode, null)
  assert.ok(n.unmeasured.some(u => u.id === 'VA.1'))
})

test('a score change is compared only against the same maximum', () => {
  const p = full()
  put(p, 'POS.7', [{ Month: '2026-08-01', Percent: 58, Max: 50 }, { Month: '2026-09-01', Percent: 60, Max: 60 }])
  const row = both(p).cs.glance.rows.find(r => r.label === 'Defender for Cloud score')
  assert.deepEqual(row.values, ['Not available', '58%', '60%'])
  assert.equal(row.change, 'Not compared, the maximum changed')
})

test('analyst highlights come only from a reviewed record for this report month', () => {
  const p = full()
  p.context = { MonthHighlights: [
    { Title: 'Phishing campaign blocked', Summary: 'A credential phishing wave was quarantined.', Reference: 'ZD 1234', Month: '2026-09', Reviewed: '2026-10-02' },
    { Title: 'Old', Summary: 'From August.', Reference: 'ZD 1', Month: '2026-08', Reviewed: '2026-09-02' },
    { Title: 'Early', Summary: 'Reviewed before the month ended.', Reference: 'ZD 2', Month: '2026-09', Reviewed: '2026-09-15' },
    { Title: 'No reference', Summary: 'x', Month: '2026-09', Reviewed: '2026-10-02' }] }
  const { cs } = both(p)
  assert.deepEqual(cs.highlights.map(h => h.title), ['Phishing campaign blocked'])
  assert.equal(cs.review.filter(r => r.title === 'Month highlight needs review').length, 3)
})

test('every string the CyberSOC model hands to a page keeps the copy rules', () => {
  const { cs } = both(full())
  for (const s of [...strings(cs), ...cs.presenter.map(n => n.text), ...cs.review.map(n => n.text)]) {
    assert.ok(!/;/.test(s), s)
    assert.ok(!/->|=>|[←-⇿]/.test(s), s)
    assert.ok(!/[\u{1f000}-\u{1faff}]/u.test(s), s)
  }
})

test('the HTML carries the monthly summary, the threat intelligence and vulnerability pages, in order and without semicolons', () => {
  const p = full()
  const nodes = {}
  const document = { title: '', body: { dataset: {} }, querySelectorAll: () => [], getElementById: id => nodes[id] || (nodes[id] = { id, textContent: id === 'report-data' ? JSON.stringify(p) : '', innerHTML: '', value: '', addEventListener() {} }) }
  vm.runInNewContext(fs.readFileSync(path.join(__dirname, '../report/report-render.js'), 'utf8'), { EbrReport: R, EbrCyberSoc: C, document, window: {} })
  const html = nodes.report.innerHTML
  assert.deepEqual([...html.matchAll(/<section class="page[^"]*" id="([a-z]+)"/g)].map(x => x[1]), ['summary', 'outcomes', 'threat', 'vulnerability', 'measured', 'controls', 'roadmap', 'posture'])
  assert.match(html, /<h1>CyberSOC monthly security report<\/h1>/)
  assert.match(html, /September 2026 at a glance/)
  assert.match(html, /Change from Aug 2026/)
  assert.match(html, /Valid Accounts \(T1078\.004\)/)
  assert.match(html, /Sep 10, 2026 \(in September 2026\)/)
  assert.match(html, /Completed in the review: email threats\./)
  assert.match(document.title, /\| CyberSOC monthly security report, September 2026$/)
  const text = html.replace(/<style[\s\S]*?<\/style>/g, '').replace(/<[^>]+>/g, ' ').replace(/&[a-z#0-9]+;/gi, ' ')
  assert.ok(!/;/.test(text), text.match(/.{0,60};.{0,60}/)?.[0])
})
