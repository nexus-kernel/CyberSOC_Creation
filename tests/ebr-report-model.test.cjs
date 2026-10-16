const { test } = require('node:test')
const assert = require('node:assert/strict')
const fs = require('node:fs')
const path = require('node:path')
const vm = require('node:vm')
const { build, clean, span, mark, MEDIAN_FLOOR, NULL_VALUE, NA_VALUE, TIERS } = require('../report/report-model.js')

function pack() {
  return {
    parameters: { ClientName: 'Example', WindowStart: '2025-11-01', WindowEnd: '2026-09-30', RecentStart: '2026-07-01', PostureReadDate: '2026-10-08', DefenderApi: 'available', Subscriptions: ['s1', 's2'], Workspaces: [{ Name: 'w1', CustomerId: 'w1' }, { Name: 'w2', CustomerId: 'w2' }] },
    manifest: [], results: {}, context: null
  }
}
function put(p, id, rows, status = 'OK') {
  p.manifest = p.manifest.filter(m => m.ResultId !== id)
  p.manifest.push({ ResultId: id, Status: status, Rows: rows.length, ReadTimeUtc: '2026-10-08T10:00:00Z' })
  p.results[id] = rows
}
function alerts(p, { auto = 10, duplicates = 0 } = {}) {
  put(p, 'P0.1-XDRDUP', [{ XdrIncidents: 20, InMultipleWorkspaces: duplicates }])
  put(p, 'OUT.1', [{ Raised: 100, Closed: 80, Open: 20, TruePositive: 3, ClosedUnclassified: 5 }])
  put(p, 'OUT.2', [{ Scope: 'All', Incidents: 80, AutoClosed: auto, MedianCloseMin: 22, P90CloseMin: 60 }, { Scope: 'High', Incidents: 30, AutoClosed: 0, MedianCloseMin: 20, P90CloseMin: 45 }])
  put(p, 'OUT.2-ANALYST', [{ Scope: 'All', Incidents: 80 - auto, AutoClosed: 0, MedianCloseMin: 25, P90CloseMin: 70 }, { Scope: 'High', Incidents: 30, AutoClosed: 0, MedianCloseMin: 20, P90CloseMin: 45 }])
  put(p, 'P0.1-BY-WORKSPACE', [{ WorkspaceId: 'w1', SourceTable: 'SecurityIncident', EarliestRecord: '2025-10-01', Records: 100 }, { WorkspaceId: 'w2', SourceTable: 'SecurityIncident', EarliestRecord: '2025-10-01', Records: 100 }])
}
const visible = m => JSON.stringify([m.headline, m.tiers, m.pillars, m.controls.map(c => [c.label, c.note, c.value]), m.priorities, m.whatNext, m.response, m.trend, m.threats])
const threat = (Threat, Severity, Tactics, Created) => ({ Threat, Severity, Tactics, Created, ExfilOrImpactTactic: /Exfiltration|Collection|Impact/.test(Tactics) })

test('client-facing copy says alerts and detections, never incidents, and writes dates instead of reporting window', () => {
  const p = pack(); alerts(p)
  put(p, 'OUT.5', [{ ProductName: 'Azure Sentinel', AlertSeverity: 'High', Alerts: 40 }])
  put(p, 'OUT.4', [threat('Multi-stage incident involving Initial access and Lateral movement', 'High', 'InitialAccess,LateralMovement', '2026-08-01')])
  const m = build(p), text = visible(m)
  assert.equal(m.threats.examples[0].title, 'Multi-stage alert involving Initial access and Lateral movement')
  assert.ok(!/\bincidents?\b/i.test(text), text.match(/.{0,40}incident.{0,40}/i)?.[0])
  assert.ok(!/reporting window/i.test(text))
  assert.ok(text.includes('Nov 1, 2025 to Sep 30, 2026'))
  assert.equal(span('2026-07-01', '2026-09-30'), 'Jul 1 to Sep 30, 2026')
})
test('response timing comes from one fixed cohort, every high severity alert created in the period and closed by collection', () => {
  const p = pack(); alerts(p)
  const m = build(p)
  assert.equal(m.response.key, 'high-full')
  assert.equal(m.response.cohort, 'High severity alerts created Nov 1, 2025 to Sep 30, 2026, closed by collection')
  assert.ok(!/closed in the (alert )?period/.test(JSON.stringify([visible(m), m.timingRationale, m.presenter])), 'OUT.2 filters on creation, so no surface says closed in the period')
  assert.deepEqual([m.response.median.value, m.response.median.note], ['20 min', 'Creation to recorded close. Based on 30 closed alerts.'])
  assert.deepEqual([m.response.p90.value, m.response.p90.note], ['45 min', 'Nine in ten alerts triaged and closed within this time. Based on 30 closed alerts.'])
  assert.deepEqual([m.response.notes, m.response.split, m.response.target, m.response.acknowledge], [[], null, null, null])
  assert.deepEqual(m.timingRationale.map(r => [r.key, r.status]), [['high-full', 'Presented.']])
})
test('a 90th percentile over one hour is presented with its note, and no other cohort or period replaces it', () => {
  const p = pack(); alerts(p)
  p.results['OUT.2'][1].P90CloseMin = 500
  p.results['OUT.2-ANALYST'][1].P90CloseMin = 500
  // A trailing three month result that would have cleared the old ladder is never used.
  put(p, 'OUT.2-RECENT', [{ Scope: 'High', Incidents: 12, AutoClosed: 0, MedianCloseMin: 29, P90CloseMin: 40 }, { Scope: 'All', Incidents: 40, AutoClosed: 5, MedianCloseMin: 25, P90CloseMin: 50 }])
  put(p, 'OUT.2-RECENT-ANALYST', [{ Scope: 'High', Incidents: 12, AutoClosed: 0, MedianCloseMin: 29, P90CloseMin: 40 }, { Scope: 'All', Incidents: 35, AutoClosed: 0, MedianCloseMin: 26, P90CloseMin: 55 }])
  const m = build(p)
  assert.equal(m.response.key, 'high-full')
  assert.deepEqual([m.response.median.value, m.response.p90.value, m.response.p90.overHour], ['20 min', '8.3 hr', true])
  assert.equal(m.response.p90.note, 'Nine in ten alerts triaged and closed within this time. Based on 30 closed alerts. Over one hour, covered in the review.')
  assert.equal(m.headline.find(t => t.label === 'Median time to close, high severity alerts').sub, 'Nine in ten triaged and closed within 8.3 hr. 90th percentile over one hour, covered in the review')
  assert.ok(m.tiers.outcomes.some(r => r.label === '90th percentile close, high severity alerts' && r.value === '8.3 hr'))
  assert.match(m.presenter.find(n => n.title === '90th percentile over one hour').text, /^One in ten high severity alerts took longer than 8\.3 hr to close\./)
  assert.equal(m.timingRationale[0].status, 'Presented. 90th percentile over one hour, covered in the review.')
  assert.equal(m.timing.find(r => r.scope === 'High').p90.value, '8.3 hr')
  assert.ok(!/29 min|40 min/.test(JSON.stringify([visible(m), m.timingRationale])), 'the trailing three month figures never stand in')
  assert.ok(!m.presenter.some(n => n.title === 'Trailing three month timing'))
})
test('a median under the 20 minute floor is presented with its note on every surface, never swapped for another cohort', () => {
  assert.equal(MEDIAN_FLOOR, 20)
  const p = pack(); alerts(p)
  p.results['OUT.2'][1].MedianCloseMin = 7
  p.results['OUT.2-ANALYST'][1].MedianCloseMin = 7
  const m = build(p)
  assert.equal(m.response.key, 'high-full')
  assert.deepEqual([m.response.median.value, m.response.median.belowFloor, m.response.p90.value], ['7 min', true, '45 min'])
  assert.equal(m.response.median.note, 'Creation to recorded close. Based on 30 closed alerts. Under 20 minutes, covered in the review.')
  assert.deepEqual(m.response.notes, ['Median under 20 minutes, covered in the review.'])
  assert.equal(m.headline.find(t => t.label === 'Median time to close, high severity alerts').value, '7 min')
  assert.equal(m.headline.find(t => t.label === 'Median time to close, high severity alerts').sub, 'Nine in ten triaged and closed within 45 min. Median under 20 minutes, covered in the review')
  assert.match(m.pillars.find(x => x.name === 'Detection and response').narrative, /High severity alerts closed at a median of 7 min\. Median under 20 minutes, covered in the review\./)
  assert.ok(m.presenter.some(n => n.title === 'Median under 20 minutes' && /7 min, under the 20 minute presentation floor/.test(n.text)))
  assert.deepEqual([m.timing.find(r => r.scope === 'High').median.value, m.timing.find(r => r.scope === 'High').median.belowFloor], ['7 min', true])
  assert.equal(m.timingRationale[0].status, 'Presented. Median under 20 minutes, covered in the review.')
  // Both notes together.
  p.results['OUT.2'][1].P90CloseMin = 90
  assert.deepEqual(build(p).response.notes, ['Median under 20 minutes, covered in the review.', '90th percentile over one hour, covered in the review.'])
})
test('timing is withheld only below the minimum sample, whatever the figures, and the tile falls back to confirmed threats', () => {
  const p = pack(); alerts(p)
  p.results['OUT.2'][1].Incidents = 4
  const m = build(p)
  assert.equal(m.response, null)
  assert.ok(m.unmeasured.some(u => u.id === 'OUT.2' && u.reason === '4 high severity alerts closed, below the minimum sample of 5'))
  assert.equal(m.timingRationale[0].status, 'Not presented: 4 high severity alerts closed, below the minimum sample of 5')
  assert.ok(m.headline.some(t => t.label === 'Confirmed threats' && t.sub === 'Alerts the SOC classified as true positives'))
  assert.equal(m.timing.find(r => r.scope === 'High').median, null, 'the deck row carries no timing below the sample')
  // Fast or slow figures on a large enough sample are always presented.
  p.results['OUT.2'][1].Incidents = 5; p.results['OUT.2'][1].MedianCloseMin = 1; p.results['OUT.2'][1].P90CloseMin = 5000
  assert.deepEqual([build(p).response.median.value, build(p).response.p90.value], ['1 min', '3.5 days'])
})
test('automation closures in the cohort are presented as two labelled rows, never silently swapped for the analyst-only figures', () => {
  const p = pack(); alerts(p)
  p.results['OUT.2'][1] = { Scope: 'High', Incidents: 30, AutoClosed: 20, MedianTriageMin: 2, MedianCloseMin: 3, P90CloseMin: 45 }
  p.results['OUT.2-ANALYST'][1] = { Scope: 'High', Incidents: 10, AutoClosed: 0, MedianTriageMin: 12, MedianCloseMin: 95, P90CloseMin: 400 }
  const m = build(p)
  assert.deepEqual([m.response.n, m.response.median.value, m.response.p90.value], [30, '3 min', '45 min'], 'the tiles keep the fixed cohort')
  assert.deepEqual(m.response.split.analyst, { label: 'Analyst-handled', n: 10, median: { value: '1.6 hr', minutes: 95 }, p90: { value: '6.7 hr', minutes: 400 }, acknowledge: { value: '12 min', minutes: 12 }, source: 'OUT.2-ANALYST. Read Oct 8, 2026.' })
  assert.deepEqual(m.response.split.automation, { label: 'Closed by automation rules', n: 20, source: 'OUT.2. Read Oct 8, 2026.' })
  assert.deepEqual(m.timingRationale.map(r => r.key), ['high-full', 'high-analyst', 'high-automation'])
  assert.match(m.timingRationale[2].status, /count only/)
  assert.match(m.presenter.find(n => n.title === 'Automation closures in the timing').text, /^Automation rules closed 20 of the 30 high severity alerts in the timing cohort, and the figures include them\. Analyst-handled alone: 10 alerts, median 1\.6 hr, 90th percentile 6\.7 hr\./)
  assert.equal(m.timing.find(r => r.scope === 'All').source, 'OUT.2. Read Oct 8, 2026.', 'the deck table reads OUT.2 for every severity')
  // An older pack without the analyst result still names the automation row.
  delete p.results['OUT.2-ANALYST']; p.manifest = p.manifest.filter(r => r.ResultId !== 'OUT.2-ANALYST')
  const older = build(p)
  assert.deepEqual([older.response.split.analyst, older.response.split.automation.n], [null, 20])
  assert.equal(older.timingRationale[1].status, 'Not available: no OUT.2-ANALYST high severity result.')
})
test('median time to acknowledge comes from MedianTriageMin beside time to close', () => {
  const p = pack(); alerts(p)
  for (const r of p.results['OUT.2']) r.MedianTriageMin = r.Scope === 'High' ? 6 : 9
  const m = build(p)
  assert.deepEqual([m.response.acknowledge.value, m.response.acknowledge.label], ['6 min', 'Median time to acknowledge, high severity alerts'])
  assert.equal(m.response.acknowledge.note, 'Creation to the first status change from New, by an analyst or an automation rule.')
  assert.deepEqual(m.timing.map(r => [r.scope, r.acknowledge.value]), [['High', '6 min'], ['All', '9 min']])
  assert.equal(m.timingRationale[0].acknowledge, '6 min')
})
test('the agreed response target compares the reported figures with it, never a share of alerts, and only from a valid context value', () => {
  const p = pack(); alerts(p)
  const withTarget = minutes => { p.context = { ResponseTargetMinutes: minutes }; return build(p) }
  const LIMITS = 'Close times are recorded in whole minutes and the percentiles are estimates, so this compares the figures with the target and does not count the alerts that met it.'
  assert.equal(build(p).response.target, null, 'no target line without the field')
  assert.equal(withTarget(30).response.target.sentence, `Against the agreed 30 min response target, the median time to close of 20 min is under it and the 90th percentile of 45 min is over it. ${LIMITS}`)
  assert.deepEqual([withTarget(120).response.target.median, withTarget(120).response.target.p90], ['under it', 'under it'])
  assert.deepEqual([withTarget(10).response.target.median, withTarget(10).response.target.p90], ['over it', 'over it'])
  // Minute boundaries: an alert closed 60 minutes and 30 seconds after creation records 60, so a figure within a
  // minute of the target is never read as meeting it.
  p.results['OUT.2'][1].MedianCloseMin = 60; p.results['OUT.2'][1].P90CloseMin = 60
  let m = withTarget(60)
  assert.deepEqual([m.response.target.median, m.response.target.p90], ['about the same as the target', 'about the same as the target'])
  assert.deepEqual([withTarget(59).response.target.median, withTarget(61).response.target.p90], ['about the same as the target', 'about the same as the target'])
  assert.deepEqual([withTarget(62).response.target.median, withTarget(58).response.target.p90], ['under it', 'over it'])
  m = withTarget(60)
  assert.ok(!/nine in ten|at least|half|share|within the agreed/i.test(m.response.target.sentence), 'no attainment share is claimed')
  assert.ok(m.presenter.some(n => n.title === 'Response target' && /no share of alerts that met the target and no SLA attainment figure/.test(n.text)))
  for (const bad of [0, -5, 12.5, 'soon', {}]) {
    const bm = withTarget(bad)
    assert.equal(bm.response.target, null, String(bad))
    assert.ok(bm.review.some(n => n.title === 'Response target needs review'), String(bad))
  }
  assert.ok(!withTarget(null).review.some(n => n.title === 'Response target needs review'), 'a null field from the example file is silent')
})
test('the operations page shows the fixed cohort with acknowledge, the labelled automation rows, the target comparison, and the presenter cohort table', () => {
  const p = pack(); alerts(p)
  p.results['OUT.2'][1] = { Scope: 'High', Incidents: 30, AutoClosed: 20, MedianTriageMin: 2, MedianCloseMin: 7, P90CloseMin: 95 }
  p.results['OUT.2-ANALYST'][1] = { Scope: 'High', Incidents: 10, AutoClosed: 0, MedianTriageMin: 12, MedianCloseMin: 45, P90CloseMin: 400 }
  p.context = { ResponseTargetMinutes: 60 }
  const nodes = {}
  const document = { body: { dataset: {} }, querySelectorAll: () => [], getElementById: id => nodes[id] || (nodes[id] = { textContent: id === 'report-data' ? JSON.stringify(p) : '', addEventListener() {} }) }
  vm.runInNewContext(fs.readFileSync(path.join(__dirname, '../report/report-render.js'), 'utf8'), { EbrReport: require('../report/report-model.js'), document, window: {} })
  const html = nodes.report.innerHTML, review = nodes.review.innerHTML
  const rowsOf = h => [...h.match(/<div class="timing">[\s\S]*?<\/table>/)[0].matchAll(/<tr>([\s\S]*?)<\/tr>/g)].map(r => r[1].replace(/<[^>]+>/g, '|').replace(/\|+/g, '|').replace(/^\||\|$/g, ''))
  assert.deepEqual(rowsOf(html), ['Alerts|Closed|Median to acknowledge|Median to close|90th percentile close', 'All high severity alerts|30|2 min|7 min|1.6 hr', 'Analyst-handled|10|12 min|45 min|6.7 hr', 'Closed by automation rules|20|Not collected|Not collected|Not collected'])
  assert.ok(html.includes('Median under 20 minutes, covered in the review. 90th percentile over one hour, covered in the review.'))
  assert.ok(html.includes('Against the agreed 1 hr response target, the median time to close of 7 min is under it and the 90th percentile of 1.6 hr is over it.'))
  assert.ok(html.includes('<caption>High severity alerts created Nov 1, 2025 to Sep 30, 2026, closed by collection</caption>'))
  assert.ok(html.includes('<span class="tile-value">7 min</span><h3>Median time to close, high severity alerts</h3>'), 'the tile presents the sub-floor median')
  assert.ok(review.includes('<h3>Response timing cohort</h3>') && !/Candidates are tried in order/.test(review))
  assert.ok(!/Response timing cohort|presentation floor/.test(html), 'the cohort audit stays in the presenter notes')
})
test('automation closures above half are removed from the headline count and shown as a supporting line', () => {
  const p = pack(); alerts(p, { auto: 50 })
  const m = build(p)
  assert.equal(m.alerts.analystMode, true)
  assert.equal(m.alerts.triaged, 50)
  assert.equal(m.alerts.closed, 30)
  assert.match(m.headline.find(t => t.label === 'Alerts triaged').sub, /Plus 50 closed by automation rules/)
  const low = pack(); alerts(low, { auto: 20 })
  assert.equal(build(low).alerts.triaged, 100)
})
test('open alerts never reach the executive page or the roadmap, and are framed as referred items with a presenter note', () => {
  const p = pack(); alerts(p)
  const m = build(p)
  assert.ok(!m.priorities.some(x => /follow-through|open alert/i.test(x.title)))
  assert.ok(!JSON.stringify(m.tiers).includes('open'))
  assert.ok(m.presenter.some(n => n.title === 'Open alerts' && /20 of 100/.test(n.text)))
  assert.equal(m.alerts.open, 20)
})
test('a weak closed share stays off the executive tier while a strong one is shown', () => {
  const p = pack(); alerts(p)
  assert.ok(!build(p).tiers.outcomes.some(r => r.label === 'Alerts closed'))
  p.results['OUT.1'][0].Closed = 95; p.results['OUT.1'][0].Open = 5
  assert.ok(build(p).tiers.outcomes.some(r => r.label === 'Alerts closed' && r.value === '95%'))
  assert.ok(!build(p).tiers.outcomes.some(r => /resolved/.test(r.label)), 'the tier says closed, never resolved')
})
test('high severity increases become presenter notes, not client notices', () => {
  const p = pack(); alerts(p)
  put(p, 'OUT.3', [{ Month: '2025-11-01', Total: 10, High: 1, Medium: 1, Low: 4, Informational: 4 }, { Month: '2026-09-01', Total: 30, High: 12, Medium: 1, Low: 4, Informational: 13 }])
  const m = build(p)
  assert.ok(m.presenter.some(n => n.title === 'High severity trend'))
  assert.ok(!visible(m).includes('increased'))
  assert.equal(m.trend.length, 2)
})
test('duplicate or unverified cross-workspace alerts withhold every alert figure', () => {
  for (const status of ['duplicates', 'unknown', 'partial']) {
    const p = pack(); alerts(p, { duplicates: status === 'duplicates' ? 3 : 0 })
    if (status === 'unknown') p.manifest = p.manifest.filter(m => m.ResultId !== 'P0.1-XDRDUP')
    if (status === 'partial') p.manifest.find(m => m.ResultId === 'P0.1-XDRDUP').Status = 'PARTIAL'
    const m = build(p)
    assert.equal(m.alerts, null)
    assert.equal(m.response, null)
    assert.deepEqual(m.trend, [])
    assert.ok(m.presenter.some(n => /reconciliation/i.test(n.title)))
  }
})
test('missing, failed, empty and invalid readings never become perfect coverage and are shown as (null)', () => {
  for (const status of ['MISSING', 'FAILED', 'UNAVAILABLE', 'EMPTY', 'SKIPPED', 'MANUAL']) {
    const p = pack()
    put(p, 'DP.1', [{ Accounts: 4, SecureTransfer: 4 }], status)
    const m = build(p)
    const c = m.controls.find(c => c.label === 'Secure transfer required on storage accounts')
    assert.equal(c.value, NULL_VALUE); assert.equal(c.value, '(null)')
    assert.equal(c.measured, false); assert.equal(c.pct, null); assert.equal(c.mark, null)
    assert.ok(!m.tiers.controls.some(r => r.id === 'DP.1'), 'ungathered controls stay off the executive summary tiers')
    assert.ok(m.unmeasured.some(u => u.id === 'DP.1' && u.reason === status))
  }
  const p = pack()
  put(p, 'DP.1', [{ Accounts: 2, SecureTransfer: 3 }])
  const m = build(p)
  assert.equal(m.controls.find(c => c.id === 'DP.1').value, '(null)')
  assert.ok(m.unmeasured.some(u => u.id === 'DP.1' && /valid reading/.test(u.reason)))
})
test('every control that could not be gathered appears as (null), and controls with no applicable resources are omitted', () => {
  const m = build(pack())
  const ungathered = m.controls.filter(c => c.measured === false)
  assert.ok(ungathered.length >= 20, `expected the full control set as (null), got ${ungathered.length}`)
  assert.ok(ungathered.every(c => c.value === '(null)' && c.pct === null && c.mark === null && c.note))
  for (const id of ['IA.1', 'IA.3', 'IA.3-DEVICECODE', 'IA.9', 'IA.9-SAFELINKS', 'IA.9-SAFEATTACH', 'EW.1', 'EW.3', 'DR.2', 'DR.4', 'DR.13', 'DR.7', 'DR.9', 'DP.7', 'NB.1', 'DP.2']) {
    assert.ok(ungathered.some(c => c.id === id), `${id} should read (null)`)
  }
  assert.deepEqual(m.tiers.controls, [])
  assert.ok(m.review.some(n => /not measured/i.test(n.title) && /\(null\)/.test(n.text)))
  const p = pack()
  put(p, 'NB.4', [{ Sites: 0, HttpsOnly: 0 }])
  const n = build(p)
  assert.ok(!n.controls.some(c => c.id === 'NB.4'), 'zero applicable resources is not a gathering failure')
  assert.ok(n.review.some(r => /NB.4: no applicable resources/.test(r.text)))
})
test('status marks follow the deck thresholds and verified configurations read as in force', () => {
  assert.equal(mark(95), 'E'); assert.equal(mark(90), 'E'); assert.equal(mark(89.9), 'P'); assert.equal(mark(50), 'P'); assert.equal(mark(49.9), 'N')
  const p = pack()
  put(p, 'IA.1', [{ UserType: 'Member', UsersSignedIn: 100, UsersChallenged: 85 }, { UserType: 'Guest', UsersSignedIn: 400, UsersChallenged: 2 }])
  put(p, 'IA.9', [{ Enabled: true, EnableTargetedUserProtection: true, EnableOrganizationDomainsProtection: true, EnableMailboxIntelligenceProtection: true, EnableSpoofIntelligence: true }])
  const m = build(p)
  const mfa = m.controls.find(c => c.id === 'IA.1')
  assert.equal(mfa.pct, 85); assert.equal(mfa.mark, 'P')
  assert.deepEqual(m.controls.filter(c => c.id === 'IA.9').map(c => [c.label, c.value]), [['Anti-phishing policy applied to every mailbox', 'In force'], ['Advanced anti-phishing policy applied', 'In force']])
  assert.ok(m.priorities.some(x => x.title === 'Multifactor authentication for every user'))
  put(p, 'IA.1', [{ UserType: 'Member', UsersSignedIn: 100, UsersChallenged: 90 }])
  const e = build(p)
  assert.equal(e.controls.find(c => c.id === 'IA.1').mark, 'E')
  assert.ok(!e.priorities.some(x => x.title === 'Multifactor authentication for every user'), 'a control at E is not a priority')
})
test('graph-backed and per-device controls read from aggregates and booleans', () => {
  const p = pack()
  put(p, 'IA.1-ADMINPORTAL', [{ UserType: 'Member', Users: 20, UsersChallenged: 19, SignIns: 300, MfaSignIns: 290 }])
  put(p, 'IA.3-DEVICECODE', [{ Attempts: 5, Succeeded: 0, BlockedByCa: 5, Users: 2, Apps: 1, InForce: true }])
  put(p, 'IA.6', [{ Standing: 4, Eligible: 6, Activated: 1, Accounts: 8 }])
  put(p, 'IA.11', [{ SignInRiskPolicies: 1, SignInRiskAllUsers: true, UserRiskPolicies: 1, UserRiskAllUsers: false, InForce: false, PasswordHashSync: 'On' }])
  put(p, 'IA.13', [{ UserConsent: 'Low risk, verified publishers', AdminConsentWorkflow: true, RiskyAppConsent: false, Governed: true }])
  put(p, 'EW.15', [{ Scope: 'Azure VM', Devices: 95, Compliant: 89 }, { Scope: 'Other device', Devices: 1668, Compliant: 1648 }])
  put(p, 'EW.16', [], 'EMPTY')
  put(p, 'EW.10', [{ Machines: 40, WithinCadence: 36, OverduePatches: 12, AssessedWithin7d: 40 }])
  put(p, 'EW.13', [{ Policies: 1, Assigned: 1 }])
  put(p, 'NB.11', [{ Scope: 'Azure VM', Devices: 100, Compliant: 0 }])
  put(p, 'DP.8', [{ SharingCapability: 'externalUserAndGuestSharing', DomainRestrictionMode: 'none' }])
  put(p, 'DP.7-ZAP', [{ Kind: 'Malware', ZapEnabled: true }, { Kind: 'Spam and phishing', PhishZapEnabled: true, SpamZapEnabled: false }])
  put(p, 'DR.10', [{ Closed: 40, WithClassification: 38, WithComment: 37, Documented: 36 }])
  put(p, 'DR.11', [{ Sensors: 3, Healthy: 2, UpToDate: 3 }])
  put(p, 'DR.13', [{ Resources: 100, AllHealthy: 90, WithGaps: 10 }])
  put(p, 'DR.6-INITIATIVE', [], 'EMPTY')
  put(p, 'DR.12', [{ Groups: 3, Devices: 1700 }])
  put(p, 'IA.14', [{ Users: 12, SignIns: 400 }])
  p.parameters.PatchCadenceDays = 30
  const m = build(p)
  const c = id => m.controls.find(x => x.id === id)
  assert.equal(c('IA.1-ADMINPORTAL').pct, 95); assert.equal(c('IA.1-ADMINPORTAL').mark, 'E')
  assert.equal(c('IA.3-DEVICECODE').value, 'In force'); assert.match(c('IA.3-DEVICECODE').note, /5 device code attempts/)
  assert.equal(c('IA.6').value, '6 of 10'); assert.equal(c('IA.6').mark, 'P')
  assert.equal(c('IA.11').value, 'Not in force'); assert.match(c('IA.11').note, /User risk policy for all users: no/)
  assert.equal(c('IA.13').value, 'In force')
  assert.equal(c('EW.15').good, 89); assert.equal(c('EW.15').total, 95, 'Azure virtual machine rows only'); assert.equal(c('EW.15').mark, 'E')
  assert.ok(!c('EW.16'), 'EMPTY per-device results are omitted, not (null)')
  assert.equal(c('EW.10').pct, 90); assert.match(c('EW.10').note, /30 days/)
  assert.equal(c('EW.13').value, 'In force')
  assert.equal(c('NB.11').mark, 'N')
  assert.equal(c('DP.8').value, 'Not in force'); assert.match(c('DP.8').note, /externalUserAndGuestSharing/)
  assert.equal(c('DP.7-ZAP').value, 'Not in force')
  assert.equal(c('DR.10').pct, 90); assert.equal(c('DR.10').mark, 'E')
  assert.equal(c('DR.11').value, '2 of 3')
  assert.equal(c('DR.13').mark, 'E')
  assert.ok(!c('DR.6-INITIATIVE'))
  assert.ok(m.review.some(n => /initiative is not assigned/.test(n.text)))
  assert.ok(m.review.some(n => /DR\.12: 1,700 onboarded Azure virtual machines across 3 device groups/.test(n.text)))
  assert.ok(m.review.some(n => /IA\.14: 12 users signed in to Azure management/.test(n.text)))
  assert.ok(!/\bincidents?\b/i.test(visible(m)))
  put(p, 'IA.13', [{ UserConsent: 'Low risk, verified publishers', AdminConsentWorkflow: '', RiskyAppConsent: false, Governed: '' }])
  put(p, 'IA.6', [{ Standing: 59, Eligible: 0, Activated: 0, Accounts: 28, PimRead: 'NoPermission' }])
  const u = build(p)
  assert.equal(u.controls.find(x => x.id === 'IA.13').value, '(null)', 'an unknown workflow is not graded as not in force')
  assert.match(u.controls.find(x => x.id === 'IA.13').note, /could not be read/)
  assert.equal(u.controls.find(x => x.id === 'IA.6').value, '(null)', 'hidden eligibility is a gap, not an N')
  assert.ok(u.unmeasured.some(x => x.id === 'IA.6' && /RoleManagement\.Read\.Directory/.test(x.reason)))
  put(p, 'IA.6', [{ Standing: 59, Eligible: 0, Activated: 0, Accounts: 28, PimRead: 'NoLicense' }])
  assert.equal(build(p).controls.find(x => x.id === 'IA.6').mark, 'N', 'without PIM licensing, all-standing is a real N')
})
test('tenant score comes from POS.6 when the context file has none, with movement from the trend, and the context file still wins', () => {
  const p = pack()
  put(p, 'POS.6', [{ ReadDate: '2026-10-10', Current: 412.5, Max: 1000, Percent: 41.25, IdentityPct: 60.4, DevicePct: 41.9, AppsPct: 30, DataPct: 55, AllTenantsAverage: 300, Snapshots: 90 }])
  put(p, 'POS.6-TREND', [{ Date: '2026-10-10', Current: 412.5, Max: 1000, Percent: 41.25 }, { Date: '2026-07-15', Current: 380, Max: 1000, Percent: 38 }])
  let m = build(p)
  assert.equal(m.tenantScore.value, 41.3)
  // Movement reads in percentage points of the maximum, with the starting percentage, as the cloud score does.
  assert.deepEqual(m.tenantScore.delta, { points: 3.3, since: 'Jul 2026', from: 38 })
  assert.equal(m.tenantScore.categories.length, 4)
  assert.match(m.tenantScore.source, /^POS\.6\./)
  assert.ok(!m.review.some(n => n.title === 'Microsoft tenant Secure Score'))
  p.results['POS.6-TREND'][1].Current = 500
  m = build(p)
  assert.equal(m.tenantScore.delta, null, 'a declining trend prints no movement line')
  p.context = { TenantScore: { Current: 400, Max: 1000, ReadDate: '2026-10-01', Source: 'Portal reading' } }
  m = build(p)
  assert.equal(m.tenantScore.current, 400); assert.equal(m.tenantScore.source, 'Portal reading')
})
test('DP.10 falls back to the BitLocker check in EW.3 when Intune encryption state is unavailable', () => {
  const p = pack()
  put(p, 'DP.10', [], 'UNAVAILABLE')
  put(p, 'EW.3', [{ Scope: 'Azure VM', ConfigurationName: 'Encrypt all BitLocker-supported drives', Devices: 95, Compliant: 0 }, { Scope: 'Other device', ConfigurationName: 'Encrypt all BitLocker-supported drives', Devices: 1668, Compliant: 1417 }, { Scope: 'Other device', ConfigurationName: 'Turn on real-time protection', Devices: 1668, Compliant: 1660 }])
  let m = build(p)
  let c = m.controls.find(x => x.id === 'DP.10')
  assert.equal(c.good, 1417); assert.equal(c.total, 1763); assert.match(c.source, /^EW\.3\./); assert.match(c.note, /BitLocker/)
  put(p, 'DP.10', [{ OperatingSystem: 'Windows', Ownership: 'company', Devices: 50, Encrypted: 48, Compliant: 45 }, { OperatingSystem: 'iOS', Ownership: 'personal', Devices: 30, Encrypted: 30, Compliant: 30 }])
  m = build(p)
  c = m.controls.find(x => x.id === 'DP.10')
  assert.equal(c.value, '48 of 50'); assert.match(c.source, /^DP\.10\./)
  const n = build(pack())
  assert.equal(n.controls.find(x => x.id === 'DP.10').value, '(null)')
})
test('cloud score uses points, shows a gain only when the trend is not declining, and keeps the tenant score for context', () => {
  const p = pack()
  put(p, 'POS.1', [{ Current: 40, Max: 80, Percent: 99, Subscriptions: 1 }])
  put(p, 'POS.7', [{ Month: '2026-07-01', Current: 36, Max: 80, Percent: 45 }, { Month: '2026-10-01', Current: 40, Max: 80, Percent: 50 }])
  let m = build(p)
  assert.equal(m.cloudScore.value, 50)
  assert.deepEqual(m.cloudScore.delta, { points: 5, since: 'Jul 2026', from: 45 })
  assert.match(m.headline.find(t => /Defender for Cloud/.test(t.label)).sub, /^Up 5 points since Jul 2026, from 45%$/)
  assert.ok(!/points across|of \d+ points/.test(m.cloudScore.note), 'the note never states the points available')
  p.results['POS.7'][0].Percent = 60
  m = build(p)
  assert.equal(m.cloudScore.delta, null)
  assert.ok(m.presenter.some(n => /score movement/i.test(n.title)))
  assert.equal(m.tenantScore, null)
  assert.ok(m.presenter.some(n => /1 of 2/.test(n.text)))
})
test('context supplies tenure, tenant score and dated delivery, and rejects malformed entries', () => {
  const p = pack(); alerts(p)
  p.context = { ServiceStartDate: '2023-08-15', TenantScore: { Current: 45, Max: 100, ReadDate: '2026-10-08', Source: 'Dated portal capture', Previous: 40, PreviousMax: 100, PreviousReadDate: '2026-07-10', Categories: { Identity: 60.4, Device: 41.9 } }, Delivered: [{ Title: 'TLS update', Outcome: 'Validated transport setting', Reference: 'CHG-123', CompletedDate: '2026-08-10' }, { Title: 'Planned', Outcome: 'Plan', Reference: 'CHG-124', CompletedDate: '2026-10-20' }] }
  const m = build(p)
  assert.equal(m.service.months, 37)
  assert.equal(m.headline[0].label, 'Months of managed security')
  assert.equal(m.tenantScore.value, 45)
  assert.deepEqual(m.tenantScore.delta, { points: 5, since: 'Jul 2026', from: 40 })
  assert.match(m.headline.find(t => /tenant Secure Score/.test(t.label)).sub, /^Up 5 points since Jul 2026, from 40%$/)
  assert.ok(!/of \d+ points/.test(m.tenantScore.note), 'the note never states the points available')
  assert.equal(m.tenantScore.categories.length, 2)
  assert.equal(m.delivered.length, 1)
  // Without PreviousMax and without a dated snapshot, the movement line is omitted and the evidence review says why.
  delete p.context.TenantScore.PreviousMax
  const unqualified = build(p)
  assert.equal(unqualified.tenantScore.delta, null)
  assert.ok(unqualified.review.some(n => n.title === 'Microsoft tenant Secure Score movement' && /without PreviousMax/.test(n.text)))
  assert.ok(!/from 40%/.test(JSON.stringify(unqualified.headline)), 'no historical percentage is asserted over the current maximum')
  p.context.TenantScore.PreviousMax = 100
  p.context.TenantScore.ReadDate = '2026-02-31'
  p.context.ServiceStartDate = '2027-01-01'
  const bad = build(p)
  assert.equal(bad.tenantScore, null)
  assert.equal(bad.service, null)
})
test('the MFA method update appears only when retiring methods are in use, and is never framed as passwordless', () => {
  const p = pack()
  put(p, 'IA.2', [{ Bucket: 'Retiring: SMS or voice', DistinctUsers: 7 }, { Bucket: 'Phishing-resistant', DistinctUsers: 3 }, { Bucket: 'Authenticator or OTP', DistinctUsers: 50 }])
  const m = build(p)
  assert.equal(m.mfaMethods.retiring, 7)
  assert.match(m.whatNext, /the proposed hardening roadmap and the recommended MFA method update ahead of February 1, 2027 \(July 1, 2027 for Global Administrators and external users\)\./)
  assert.ok(!/already scoped|sequenced hardening/.test(m.whatNext), 'the summary never says the update is already scoped')
  const update = m.priorities.find(x => x.id === 'IA.2')
  assert.equal(update.title, 'MFA method update')
  // Passkeys are the recommended target, Authenticator push stays supported, and a telephony provider is only for a
  // documented need (Oct 16, 2026, from Microsoft's retirement page dated Sep 23, 2026).
  assert.match(update.action, /register each one on a passkey in Microsoft Authenticator, Windows Hello for Business or a FIDO2 security key in guided waves/)
  assert.match(update.action, /Microsoft Authenticator push is outside this retirement and stays supported\. A telephony provider from Microsoft Security Store is kept only for a documented regulatory or operational need\./)
  assert.equal(update.evidence, '7 users signed in with text message or voice in the last 30 days. Microsoft retires these methods on February 1, 2027 (July 1, 2027 for Global Administrators and external users). Whether these users hold another registered MFA method is not yet evaluated.')
  assert.equal(m.mfaMethods.phoneOnly, null)
  assert.match(m.mfaMethods.timeline, /^From September 1, 2026, Microsoft enables passkeys for users enabled for text message or voice and prompts them to register one when they complete MFA\. Microsoft retires its text message and voice delivery on February 1, 2027 for most users and on July 1, 2027 for Global Administrators and external users\. After the applicable date, a user whose only available MFA method is text message or voice must register a passkey before signing in again, and this blocking prompt has no opt-out\.$/)
  assert.deepEqual(m.mfaMethods.steps.map(([head]) => head), ['Notify the affected users', 'Register a passkey', 'Remove the retiring methods', 'Confirm readiness early'])
  assert.match(m.mfaMethods.steps[3][1], /before Feb 1, 2027 \(Jul 1, 2027 for Global Administrators and external users\)/)
  // The outcome is measurable, never a promise that the date arrives as a non-event (Oct 16, 2026).
  assert.equal(update.success, 'Every affected user registered on a replacement method before February 1, 2027 (July 1, 2027 for Global Administrators and external users), the fallback tested, and no rise in failed sign-ins after enforcement.')
  assert.equal(m.mfaMethods.outcome, update.success)
  assert.ok(!/non-event|no sign-in is blocked/.test(JSON.stringify(m)), 'no outcome promise')
  assert.ok(!/passwordless/i.test(JSON.stringify([m.priorities, m.whatNext, m.pillars, m.mfaMethods])), 'no passwordless programme wording')
  assert.ok(!/need to update their MFA method|still rel(y|ies)|Microsoft Authenticator or a phishing-resistant/.test(JSON.stringify(m)), 'use alone is never read as sole reliance')
  put(p, 'IA.2', [{ Bucket: 'Authenticator app or OTP token', DistinctUsers: 50 }])
  assert.ok(!/February/.test(build(p).whatNext))
})
test('the MFA method update reads sole reliance only from the IA.5 registration count, never from use', () => {
  const p = pack()
  put(p, 'IA.2', [{ Bucket: 'Retiring: SMS or voice', DistinctUsers: 7 }, { Bucket: 'Authenticator or OTP', DistinctUsers: 50 }])
  const ia5 = { Members: 200, MfaRegistered: 180, PhishingResistant: 25, PhoneRegistered: 90, AuthenticatorRegistered: 150 }
  put(p, 'IA.5', [{ ...ia5, PhoneOnly: 4 }])
  let m = build(p)
  assert.equal(m.mfaMethods.phoneOnly, 4)
  assert.equal(m.mfaMethods.reliance, 'The registration read finds 4 members whose only registered MFA method is text message or voice.')
  assert.ok(m.priorities.find(x => x.id === 'IA.2').evidence.endsWith(' The registration read finds 4 members whose only registered MFA method is text message or voice.'))
  assert.match(m.mfaMethods.source, /^IA\.2\. Read .*\. IA\.5\. Read .*\. Registered methods, members only\.$/)
  put(p, 'IA.5', [{ ...ia5, PhoneOnly: 1 }])
  assert.equal(build(p).mfaMethods.reliance, 'The registration read finds 1 member whose only registered MFA method is text message or voice.')
  put(p, 'IA.5', [{ ...ia5, PhoneOnly: 0 }])
  assert.equal(build(p).mfaMethods.reliance, 'The registration read finds no member whose only registered MFA method is text message or voice.')
  // A pack collected before PhoneOnly, a partial read and a missing read all leave reliance not yet evaluated.
  for (const [rows, status] of [[[ia5], 'OK'], [[{ ...ia5, PhoneOnly: 4 }], 'PARTIAL'], [[], 'UNAVAILABLE']]) {
    put(p, 'IA.5', rows, status)
    m = build(p)
    assert.equal(m.mfaMethods.phoneOnly, null, status)
    assert.equal(m.mfaMethods.reliance, 'Whether these users hold another registered MFA method is not yet evaluated.')
    assert.ok(!/IA\.5/.test(m.mfaMethods.source))
  }
})
test('ticket scope is recorded from the collector and flagged when absent', () => {
  const p = pack(); alerts(p)
  let m = build(p)
  assert.equal(m.ticketed, false)
  assert.ok(m.presenter.some(n => n.title === 'Alert scope' && /before the ticket scope rule/.test(n.text)))
  p.parameters.TicketPattern = '(?i)zendesk'
  m = build(p)
  assert.equal(m.ticketed, true)
  assert.ok(!m.presenter.some(n => n.title === 'Alert scope'))
  assert.ok(m.review.some(n => n.title === 'Alert scope'))
  assert.match(m.alerts.source, /opened an Atmosera ticket/)
})
test('empty packs still produce a complete model with no exceptions', () => {
  assert.doesNotThrow(() => build({}))
  const m = build({})
  assert.equal(m.response, null)
  assert.equal(m.alerts, null)
  assert.equal(m.priorities[0].title, 'Baseline validation')
  assert.equal(m.pillars.length, 5)
})
test('presentation copy removes prohibited symbols and punctuation', () => {
  assert.equal(clean('One; two → three > four 😀'), 'One. two three four')
})
test('real packs agree with their client-level source results and expose no private fields', t => {
  const root = path.resolve(__dirname, '..')
  const dirs = fs.readdirSync(root).filter(n => n.startsWith('EBR-Evidence_') && fs.existsSync(path.join(root, n, '03-security-report.html')))
  if (!dirs.length) { t.skip('No local evidence packs present'); return }
  for (const dir of dirs) {
    const html = fs.readFileSync(path.join(root, dir, '03-security-report.html'), 'utf8')
    const data = JSON.parse(html.match(/<script id="report-data" type="application\/json">([\s\S]*?)<\/script>/)[1])
    const m = build(data)
    if (m.alerts) assert.equal(m.alerts.raised, data.results['OUT.1'][0].Raised)
    assert.equal(m.subscriptions, new Set(data.parameters.Subscriptions).size)
    assert.equal(m.workspaces.length, data.parameters.Workspaces.length)
    for (const field of ['ClassificationComment', 'AccountUpn', 'VmName', 'DeviceName', 'SubnetName', '"Title"', 'AccountDisplayName']) assert.ok(!html.includes(field), `${dir} embeds ${field}`)
    assert.ok(!/\bincidents?\b/i.test(visible(m)), dir)
  }
})

test('every control is placed in a pillar and a tier that follows the controls baseline', () => {
  const m = build(pack())
  const groups = ['Identity and access', 'Endpoint and workload', 'Network and boundary', 'Data protection', 'Detection and response']
  assert.ok(m.controls.length >= 20)
  assert.ok(m.controls.every(c => ['foundational', 'defense'].includes(c.tier) && groups.includes(c.group)), 'a control without a tier or pillar')
  assert.deepEqual(TIERS, { foundational: 'Foundational', defense: 'Defense in depth' })
  const tierOf = label => m.controls.find(c => c.label === label)?.tier
  assert.equal(tierOf('Multifactor authentication required at sign-in'), 'foundational')
  assert.equal(tierOf('Legacy authentication blocked'), 'foundational')
  assert.equal(tierOf('Location-based sign-in access controls enforced through Conditional Access'), 'foundational')
  assert.equal(tierOf('Conditional Access evaluated at sign-in'), undefined, 'replaced by the location row on Oct 12, 2026')
  assert.equal(tierOf('Anti-phishing policy applied to every mailbox'), 'foundational')
  assert.equal(tierOf('Advanced anti-phishing policy applied'), 'defense')
  assert.equal(tierOf('Privileged roles held through eligibility rather than standing assignment'), 'defense')
  assert.equal(tierOf('Identity Protection sign-in and user risk policies enforced'), 'defense')
  assert.equal(tierOf('Application consent governed by administrative approval'), 'defense')
  assert.equal(tierOf('Azure virtual machines reporting to endpoint detection'), 'foundational')
  assert.equal(tierOf('Endpoint detection and response deployed'), undefined, 'the fleet-wide row went with the Azure virtual machine scope on Oct 14, 2026')
  assert.equal(tierOf('Real-time anti-malware protection enabled'), 'foundational')
  assert.equal(tierOf('Vulnerability assessment running on onboarded Azure virtual machines'), 'defense')
  assert.equal(tierOf('Platform integrity through Trusted Launch'), 'defense')
  assert.equal(tierOf('Encryption at host on virtual machines'), 'defense')
  assert.equal(tierOf('Application allow-listing policy assigned'), 'defense')
  assert.equal(tierOf('Encryption in transit enforced on published web apps'), 'foundational')
  assert.equal(tierOf('Blob containers closed to anonymous access'), 'defense')
  assert.equal(tierOf('Workload subnets protected by segmentation'), 'defense')
  assert.equal(tierOf('App Service minimum TLS 1.2'), 'foundational')
  assert.equal(tierOf('Storage accounts closed to public networks'), 'defense')
  assert.equal(tierOf('Anonymous blob access disabled'), 'foundational')
  assert.equal(tierOf('Secure transfer required on storage accounts'), 'foundational')
  assert.equal(tierOf('Key Vault purge protection'), 'foundational')
  assert.equal(tierOf('Key Vault access governed by role-based access control'), 'defense')
  assert.equal(tierOf('Azure Backup protecting virtual machines'), 'defense')
  assert.equal(tierOf('Safe Links scanning on mail, Teams and Office'), 'foundational')
  assert.equal(tierOf('Cloud workload protection across the resource estate'), 'foundational')
  assert.equal(tierOf('Diagnostic logging enabled on platform resources'), undefined, 'DR.6 duplicated DR.13 and has no row')
  assert.equal(tierOf('Diagnostic logging enabled on all platform resources'), 'defense')
  assert.equal(tierOf('Analytics rules enabled in Sentinel'), 'defense')
  assert.equal(tierOf('Threat intelligence indicators ingested tenant-wide'), 'defense')
  const sensors = m.controls.find(c => c.label === 'Endpoint sensors active on onboarded Azure virtual machines')
  assert.equal(sensors.tier, 'foundational'); assert.equal(sensors.group, 'Detection and response')
  assert.deepEqual(m.tierSummary.foundational, { label: 'Foundational', enforced: 0, measured: 0, total: m.controls.filter(c => c.tier === 'foundational').length })
  assert.deepEqual(m.tierSummary.defense, { label: 'Defense in depth', enforced: 0, measured: 0, total: m.controls.filter(c => c.tier === 'defense').length })
  assert.deepEqual(m.tiers.controls, [], 'no tier totals when nothing was measured')
})
test('the default anti-phishing policy decides the foundational row and the advanced flags decide the defense row', () => {
  const p = pack()
  put(p, 'IA.9', [
    { Name: 'Office365 AntiPhish Default', IsDefault: true, Enabled: true, EnableTargetedUserProtection: false, EnableOrganizationDomainsProtection: false, EnableMailboxIntelligenceProtection: false, EnableSpoofIntelligence: true },
    { Name: 'Custom', IsDefault: false, Enabled: false, EnableTargetedUserProtection: true, EnableOrganizationDomainsProtection: true, EnableMailboxIntelligenceProtection: true, EnableSpoofIntelligence: true }
  ])
  let m = build(p)
  let rows = m.controls.filter(c => c.id === 'IA.9')
  assert.deepEqual(rows.map(c => [c.tier, c.value]), [['foundational', 'In force'], ['defense', 'Not in force']], 'default on, custom disabled')
  assert.ok(m.pillars[0].narrative.includes('default anti-phishing policy covers every mailbox'))
  p.results['IA.9'][1].Enabled = true
  m = build(p)
  rows = m.controls.filter(c => c.id === 'IA.9')
  assert.deepEqual(rows.map(c => [c.tier, c.value]), [['foundational', 'In force'], ['defense', 'In force']], 'custom enabled')
  assert.ok(m.pillars[0].narrative.includes('advanced anti-phishing policy protects every mailbox'))
  put(p, 'IA.9', [], 'EMPTY')
  m = build(p)
  assert.deepEqual(m.controls.filter(c => c.id === 'IA.9').map(c => c.value), ['Not in force', 'Not in force'], 'no policy at all')
})
test('tier totals lead the executive control tier and foundational drift gets a presenter note', () => {
  const p = pack()
  put(p, 'DP.2', [{ Vaults: 6, SoftDelete: 6, PurgeProtection: 0, RbacAuth: 3 }])
  put(p, 'IA.9', [{ Enabled: true, EnableTargetedUserProtection: true, EnableOrganizationDomainsProtection: true, EnableMailboxIntelligenceProtection: true, EnableSpoofIntelligence: true }])
  const m = build(p)
  assert.deepEqual(m.tierSummary.foundational, { label: 'Foundational', enforced: 2, measured: 3, total: m.tierSummary.foundational.total })
  assert.deepEqual(m.tierSummary.defense, { label: 'Defense in depth', enforced: 1, measured: 2, total: m.tierSummary.defense.total })
  assert.deepEqual(m.tiers.controls.slice(0, 2).map(r => [r.label, r.value, r.id]), [['Foundational controls enforced', '2 of 3', 'TIER.FOUNDATIONAL'], ['Defense in depth controls enforced', '1 of 2', 'TIER.DEFENSE']])
  assert.ok(m.tiers.controls.length <= 6)
  const drift = m.presenter.find(n => n.title === 'Foundational controls below E')
  assert.ok(drift, 'foundational gap note')
  assert.match(drift.text, /1 foundational control reads below E: Key Vault purge protection \(DP.2, 0%\)/)
  assert.match(drift.text, /never regressed/, 'the presenter is told not to claim a regression')
  assert.ok(!/role-based/.test(drift.text), 'defense in depth controls are not foundational gaps')
  assert.ok(!JSON.stringify(m.tiers).includes('(null)'))
  assert.match(m.whatNext, /foundational and defense in depth controls/)
})

// Conditional Access evaluation (collector 1.10.0). IA.8-CA is the per-control count the report builder derives.
function caRow(flow, overrides = {}) {
  return { Flow: flow, PolicyRead: true, PolicyState: 'Enforced', EnforcedPolicies: 1, ExcludedIdentities: 12, DetailRead: true, SignIns: 0, SucceededExcluded: 0, AccountsExcluded: 0, SucceededUngoverned: 0, AccountsUngoverned: 0, ...overrides }
}
test('a device code block policy with excluded accounts reads in force, and the sign-ins are framed as approved exceptions', () => {
  const p = pack()
  put(p, 'IA.3-DEVICECODE', [{ Attempts: 5, Succeeded: 5, BlockedByCa: 0, Users: 5, Apps: 4, InForce: false }])
  put(p, 'IA.8-CA', [caRow('Device code', { SignIns: 5, SucceededExcluded: 5, AccountsExcluded: 5 })])
  let m = build(p)
  let c = m.controls.find(x => x.id === 'IA.3-DEVICECODE')
  assert.equal(c.value, 'In force'); assert.equal(c.mark, 'E')
  assert.match(c.note, /An enabled Conditional Access policy blocks device code flow for all users\./)
  assert.match(c.note, /5 successful sign-ins came from 5 accounts the policy excludes as approved exceptions\./)
  assert.ok(!m.presenter.some(n => /Device code/.test(n.title)))
  put(p, 'IA.8-CA', [caRow('Device code', { SignIns: 5, SucceededExcluded: 3, AccountsExcluded: 3, SucceededUngoverned: 2, AccountsUngoverned: 1 })])
  m = build(p)
  assert.equal(m.controls.find(x => x.id === 'IA.3-DEVICECODE').value, 'In force', 'the policy configuration decides the status')
  assert.ok(m.presenter.some(n => n.title === 'Device code sign-ins outside the block policy' && /2 successful device code sign-ins/.test(n.text)))
  put(p, 'IA.8-CA', [caRow('Device code', { PolicyState: 'Report-only', SignIns: 5, SucceededUngoverned: 5, AccountsUngoverned: 5 })])
  c = build(p).controls.find(x => x.id === 'IA.3-DEVICECODE')
  assert.equal(c.value, 'Not in force'); assert.match(c.note, /runs in report-only mode/)
})
test('without a policy inventory, no sign-ins means N/A and successful sign-ins mean not in force with a presenter note', () => {
  const p = pack()
  put(p, 'IA.3-DEVICECODE', [], 'EMPTY')
  put(p, 'IA.3', [], 'EMPTY')
  put(p, 'IA.1-ADMINPORTAL', [], 'EMPTY')
  put(p, 'IA.1', [], 'EMPTY')
  let m = build(p)
  assert.equal(m.controls.find(x => x.id === 'IA.4-LOCATION').value, NULL_VALUE, 'the location row needs a policy inventory')
  for (const id of ['IA.3-DEVICECODE', 'IA.3', 'IA.1-ADMINPORTAL', 'IA.1']) {
    const c = m.controls.find(x => x.id === id)
    assert.equal(c.value, NA_VALUE, id); assert.equal(c.value, 'N/A'); assert.equal(c.na, true)
    assert.equal(c.pct, null); assert.equal(c.mark, null)
    assert.match(c.note, /no evidence either way/)
  }
  assert.deepEqual([m.tierSummary.foundational.measured, m.tierSummary.foundational.enforced], [0, 0], 'N/A never moves a count')
  assert.ok(!m.unmeasured.some(u => u.id === 'IA.3-DEVICECODE'), 'N/A is not a gathering gap')
  assert.ok(m.review.some(n => n.title === 'Controls without evidence either way' && /Device code flow sign-ins blocked \(IA.3-DEVICECODE\)/.test(n.text)))
  put(p, 'IA.3-DEVICECODE', [{ Attempts: 5, Succeeded: 5, BlockedByCa: 0, Users: 5, Apps: 4, InForce: false }])
  m = build(p)
  assert.equal(m.controls.find(x => x.id === 'IA.3-DEVICECODE').value, 'Not in force')
  assert.ok(m.presenter.some(n => n.title === 'Device code exclusions not checked'))
  put(p, 'IA.3-DEVICECODE', [{ Attempts: 4, Succeeded: 0, BlockedByCa: 4, Users: 2, Apps: 1, InForce: true }])
  const dc = build(p).controls.find(x => x.id === 'IA.3-DEVICECODE')
  assert.equal(dc.value, 'In force', 'blocked attempts are evidence')
  assert.match(dc.note, /Conditional Access stopped 4 and none succeeded\./)
})
test('a policy inventory is evidence when no sign-ins of the kind happened', () => {
  const p = pack()
  put(p, 'IA.3-DEVICECODE', [], 'EMPTY')
  put(p, 'IA.3', [], 'EMPTY')
  put(p, 'IA.1-ADMINPORTAL', [], 'EMPTY')
  put(p, 'IA.8-CA', [caRow('Device code', { PolicyState: 'None', DetailRead: true }), caRow('Legacy authentication', { PolicyState: 'Security defaults' }), caRow('Admin portals', { DetailRead: false })])
  const m = build(p)
  const c = id => m.controls.find(x => x.id === id)
  assert.equal(c('IA.3-DEVICECODE').value, 'Not in force'); assert.match(c('IA.3-DEVICECODE').note, /No Conditional Access policy blocks device code flow\. No device code sign-ins in the last 30 days\./)
  assert.equal(c('IA.3').value, 'In force'); assert.match(c('IA.3').note, /Security defaults block legacy authentication/)
  assert.equal(c('IA.1-ADMINPORTAL').value, 'In force'); assert.match(c('IA.1-ADMINPORTAL').note, /requires multifactor authentication on the Microsoft admin portals/)
  assert.ok(!m.controls.some(x => x.na))
})
test('legacy authentication is graded by the block policy, ignores Unknown clients and never counts failed attempts as blocked', () => {
  const p = pack()
  put(p, 'IA.3', [{ ClientAppUsed: 'Unknown', Attempts: 182, Succeeded: 58, BlockedByCa: 0, Users: 10 }, { ClientAppUsed: 'Authenticated SMTP', Attempts: 124, Succeeded: 57, BlockedByCa: 0, Users: 1 }, { ClientAppUsed: 'Other clients', Attempts: 51, Succeeded: 0, BlockedByCa: 0, Users: 0 }])
  let m = build(p)
  let c = m.controls.find(x => x.id === 'IA.3')
  assert.equal(c.label, 'Legacy authentication blocked')
  assert.deepEqual([c.value, c.mark, c.good], ['Not in force', 'N', null], 'a success without a policy inventory is not in force')
  assert.match(c.note, /175 legacy protocol attempts in the last 30 days, 57 succeeded\./, 'Unknown is not a legacy protocol')
  assert.ok(m.presenter.some(n => n.title === 'Legacy authentication exclusions not checked'))
  const early = m.presenter.find(n => n.title === 'Legacy sign-ins that failed without a Conditional Access block')
  assert.ok(early); assert.match(early.text, /118 legacy protocol attempts failed without a Conditional Access block, most often on a wrong password/)
  assert.ok(!/did not succeed|attempts blocked/.test(visible(m)), 'failed attempts are never presented as blocked')
  put(p, 'IA.8-CA', [caRow('Legacy authentication', { SignIns: 57, SucceededExcluded: 57, AccountsExcluded: 1 })])
  c = build(p).controls.find(x => x.id === 'IA.3')
  assert.deepEqual([c.value, c.mark], ['In force', 'E'])
  assert.match(c.note, /An enabled Conditional Access policy blocks legacy authentication for all users\. 175 legacy protocol attempts in the last 30 days, 57 succeeded\./)
  assert.match(c.note, /57 successful sign-ins came from 1 account the policy excludes/)
  put(p, 'IA.3', [{ ClientAppUsed: 'Other clients', Attempts: 534, Succeeded: 16, BlockedByCa: 43, Users: 2 }])
  assert.match(build(p).controls.find(x => x.id === 'IA.3').note, /534 legacy protocol attempts in the last 30 days\. Conditional Access stopped 43 and 16 succeeded\./)
  put(p, 'IA.8-CA', [caRow('Legacy authentication', { PolicyState: 'Report-only', SignIns: 16, SucceededUngoverned: 16, AccountsUngoverned: 6 })])
  c = build(p).controls.find(x => x.id === 'IA.3')
  assert.equal(c.value, 'Not in force'); assert.match(c.note, /runs in report-only mode/)
  put(p, 'IA.8-CA', [caRow('Legacy authentication', { SignIns: 16, SucceededExcluded: 10, AccountsExcluded: 1, SucceededUngoverned: 6, AccountsUngoverned: 2 })])
  m = build(p)
  assert.equal(m.controls.find(x => x.id === 'IA.3').value, 'In force', 'the policy configuration decides the status')
  assert.ok(m.presenter.some(n => n.title === 'Legacy sign-ins outside the block policy' && /6 successful legacy sign-ins/.test(n.text)))
})
test('without a policy inventory, legacy and device code rows read in force only when Conditional Access blocks are recorded', () => {
  const p = pack()
  put(p, 'IA.3', [{ ClientAppUsed: 'Other clients', Attempts: 534, Succeeded: 0, BlockedByCa: 0, Users: 0 }])
  put(p, 'IA.3-DEVICECODE', [{ Attempts: 5, Succeeded: 0, BlockedByCa: 0, Users: 2, Apps: 1, InForce: true }])
  let m = build(p)
  for (const id of ['IA.3', 'IA.3-DEVICECODE']) {
    const c = m.controls.find(x => x.id === id)
    assert.deepEqual([c.value, c.na, c.mark], ['N/A', true, null], id)
    assert.match(c.note, /No attempt reached a Conditional Access block and there is no policy inventory, so there is no evidence either way\./, id)
  }
  assert.match(m.controls.find(x => x.id === 'IA.3').note, /^534 legacy protocol attempts in the last 30 days, none succeeded\./)
  put(p, 'IA.3', [{ ClientAppUsed: 'Other clients', Attempts: 534, Succeeded: 0, BlockedByCa: 43, Users: 0 }])
  const c = build(p).controls.find(x => x.id === 'IA.3')
  assert.equal(c.value, 'In force'); assert.match(c.note, /Conditional Access stopped 43 and none succeeded\./)
})
test('the identity pillar says legacy authentication is blocked only when the row is in force, with no attempt share', () => {
  const p = pack()
  put(p, 'IA.1', [{ UserType: 'Member', UsersSignedIn: 100, UsersChallenged: 95 }])
  put(p, 'IA.3', [{ ClientAppUsed: 'Other clients', Attempts: 51, Succeeded: 0, BlockedByCa: 0, Users: 0 }])
  put(p, 'IA.8-CA', [caRow('Legacy authentication', {})])
  let id = build(p).pillars.find(x => x.name === 'Identity and access')
  // 95 of 100 is E, but five members are left, so the headline leads with the ratio rather than reading as everyone.
  assert.equal(id.headline, 'Multifactor authentication covers 95 of 100 members at sign-in, with 5 remaining, and legacy protocols are blocked')
  assert.match(id.narrative, /Legacy authentication is blocked\./)
  put(p, 'IA.1', [{ UserType: 'Member', UsersSignedIn: 100, UsersChallenged: 100 }])
  assert.equal(build(p).pillars.find(x => x.name === 'Identity and access').headline, 'Sign-ins are challenged and legacy protocols are blocked')
  put(p, 'IA.8-CA', [caRow('Legacy authentication', { PolicyState: 'Report-only' })])
  id = build(p).pillars.find(x => x.name === 'Identity and access')
  assert.equal(id.headline, 'Sign-ins are challenged for multifactor authentication')
  put(p, 'IA.1', [{ UserType: 'Member', UsersSignedIn: 100, UsersChallenged: 95 }])
  id = build(p).pillars.find(x => x.name === 'Identity and access')
  assert.equal(id.headline, 'Multifactor authentication covers 95 of 100 members at sign-in, with 5 remaining')
  assert.ok(!/legacy/i.test(id.headline + id.narrative + JSON.stringify(id.callout) + JSON.stringify(id.measure)))
})
test('legacy failures without a Conditional Access block are never split when security defaults may have blocked them', () => {
  const p = pack()
  put(p, 'IA.3', [{ ClientAppUsed: 'IMAP4', Attempts: 1200, Succeeded: 0, BlockedByCa: 0, Users: 0 }])
  put(p, 'IA.8-CA', [caRow('Legacy authentication', { PolicyState: 'Security defaults' })])
  let m = build(p)
  assert.equal(m.controls.find(x => x.id === 'IA.3').value, 'In force')
  const n = m.presenter.find(x => x.title === 'Legacy sign-ins that failed without a Conditional Access block')
  assert.ok(n); assert.match(n.text, /cannot be split between security defaults blocks and wrong passwords/)
  put(p, 'IA.3', [{ ClientAppUsed: 'IMAP4', Attempts: 10, Succeeded: 0, BlockedByCa: 10, Users: 0 }])
  assert.ok(!build(p).presenter.some(x => x.title === 'Legacy sign-ins that failed without a Conditional Access block'), 'every failure was a Conditional Access block')
  put(p, 'IA.3', [{ ClientAppUsed: 'IMAP4', Attempts: 10, Succeeded: 0, Users: 0 }])
  assert.ok(!build(p).presenter.some(x => x.title === 'Legacy sign-ins that failed without a Conditional Access block'), 'a pack without BlockedByCa cannot tell blocks from other failures')
})
test('an enforced legacy block policy carries the identity pillar without IA.1, and reads in force when IA.3 is missing', () => {
  const p = pack()
  put(p, 'IA.3', [{ ClientAppUsed: 'IMAP4', Attempts: 10, Succeeded: 0, BlockedByCa: 10, Users: 0 }])
  put(p, 'IA.8-CA', [caRow('Legacy authentication', {})])
  const id = build(p).pillars.find(x => x.name === 'Identity and access')
  assert.deepEqual([id.measure, id.callout], [null, null])
  assert.ok(id.narrative.includes('Legacy authentication is blocked.'))
  assert.match(id.source, /^IA\.3\./)
  delete p.results['IA.3']; p.manifest = p.manifest.filter(r => r.ResultId !== 'IA.3')
  const c = build(p).controls.find(x => x.id === 'IA.3')
  assert.deepEqual([c.value, c.mark], ['In force', 'E'])
})
test('network virtual appliances get a review note and a line on the VM controls they leave', () => {
  const p = pack()
  put(p, 'P0.6-APPLIANCES', [{ Appliances: 3 }])
  put(p, 'EW.7', [{ VMs: 21, TrustedLaunchOrCvm: 0 }])
  const m = build(p)
  assert.ok(m.review.some(n => n.title === 'Network virtual appliances' && /3 machines run a marketplace firewall/.test(n.text)))
  assert.match(m.controls.find(x => x.id === 'EW.7').note, /3 network virtual appliances are excluded/)
  assert.ok(!build(pack()).review.some(n => n.title === 'Network virtual appliances'))
})
test('diagnostic logging is graded per resource by DR.13 and the backlog follows it', () => {
  const p = pack()
  put(p, 'DR.6', [{ Recommendation: 'Resource logs', Healthy: 10, Unhealthy: 40 }])
  put(p, 'DR.13', [{ Resources: 50, AllHealthy: 20, WithGaps: 30 }])
  const m = build(p)
  assert.ok(!m.controls.some(c => c.id === 'DR.6'))
  assert.equal(m.controls.find(c => c.id === 'DR.13').tier, 'defense')
  const pr = m.priorities.find(x => x.title === 'Diagnostic logging coverage')
  assert.equal(pr.id, 'DR.13'); assert.match(pr.evidence, /30 platform resources are missing at least one diagnostic or audit log setting/)
  assert.ok(m.hardening.some(h => h.id === 'DR.13' && h.value === 30))
})
test('packs with only the flattened policy inventory treat successes under an all-users block policy as outside its scope', () => {
  const p = pack()
  put(p, 'IA.3-DEVICECODE', [{ Attempts: 5, Succeeded: 5, BlockedByCa: 0, Users: 5, Apps: 4, InForce: false }])
  put(p, 'IA.3', [{ ClientAppUsed: 'Authenticated SMTP', Attempts: 124, Succeeded: 57, BlockedByCa: 0, Users: 1 }, { ClientAppUsed: 'Other clients', Attempts: 51, Succeeded: 0, BlockedByCa: 0, Users: 0 }])
  put(p, 'IA.8-CA', [caRow('Device code', { DetailRead: false }), caRow('Legacy authentication', { DetailRead: false })])
  const m = build(p)
  const dc = m.controls.find(x => x.id === 'IA.3-DEVICECODE'), lg = m.controls.find(x => x.id === 'IA.3')
  assert.equal(dc.value, 'In force')
  assert.match(dc.note, /5 device code attempts in the last 30 days\. All 5 succeeded from accounts outside the policy scope\./)
  assert.deepEqual([lg.value, lg.mark], ['In force', 'E'])
  assert.match(lg.note, /175 legacy protocol attempts in the last 30 days, 57 succeeded\. 57 successful sign-ins came from accounts outside the policy scope\./)
  const n = m.presenter.find(x => x.title === 'Conditional Access exceptions not itemized')
  assert.ok(n); assert.match(n.text, /5 device code sign-ins and 57 legacy protocol sign-ins succeeded/)
  put(p, 'IA.8-CA', [caRow('Device code', { DetailRead: false, PolicyState: 'Report-only' })])
  assert.equal(build(p).controls.find(x => x.id === 'IA.3-DEVICECODE').value, 'Not in force', 'only an enforced policy puts successes outside its scope')
})
test('an Unknown policy state is not evidence, so the sign-ins decide or the control reads N/A', () => {
  const p = pack()
  put(p, 'IA.3', [], 'EMPTY')
  put(p, 'IA.8-CA', [caRow('Legacy authentication', { PolicyState: 'Unknown', DetailRead: false })])
  assert.equal(build(p).controls.find(x => x.id === 'IA.3').value, 'N/A')
})

test('location-based access is graded from the policy inventory and replaces the share of sign-ins Conditional Access evaluated', () => {
  const p = pack()
  put(p, 'IA.8-POLICIES', [{ id: 'x' }])
  put(p, 'IA.4', [{ ConditionalAccessStatus: 'notApplied', Users: 5, SignIns: 100 }])
  put(p, 'IA.8-CA', [caRow('Location', { ExcludedIdentities: 8 })])
  let m = build(p)
  let c = m.controls.find(x => x.id === 'IA.4-LOCATION')
  assert.deepEqual([c.value, c.mark, c.tier, c.group], ['In force', 'E', 'foundational', 'Identity and access'])
  assert.equal(c.note, 'An enabled Conditional Access policy restricts sign-ins by location for all users.')
  assert.match(c.source, /^IA.4-LOCATION from IA.8-POLICIES\. Read Oct 8, 2026\./)
  assert.ok(!m.controls.some(x => x.id === 'IA.4'), 'IA.4 no longer has a row')
  assert.ok(m.presenter.some(n => n.title === 'Location policy exceptions' && /8 users, groups or roles are excluded/.test(n.text)))
  assert.ok(!/roles? (is|are) excluded/.test(visible(m)), 'exclusion counts stay in the presenter notes')
  assert.ok(m.pillars[0].narrative.includes('Conditional Access restricts sign-ins by location for every user.'))
  for (const [state, text] of [['Scoped', /applies to selected users, applications or conditions only/], ['Report-only', /runs in report-only mode/], ['None', /No Conditional Access policy restricts sign-ins by location/]]) {
    put(p, 'IA.8-CA', [caRow('Location', { PolicyState: state, EnforcedPolicies: 0, ExcludedIdentities: 0 })])
    c = build(p).controls.find(x => x.id === 'IA.4-LOCATION')
    assert.equal(c.value, 'Not in force', state); assert.match(c.note, text)
  }
  // The flattened inventory before collector 1.10.0 never recorded locations.
  put(p, 'IA.8-CA', [caRow('Location', { PolicyState: 'Unknown' })])
  m = build(p)
  assert.equal(m.controls.find(x => x.id === 'IA.4-LOCATION').value, NULL_VALUE)
  assert.ok(m.unmeasured.some(u => u.id === 'IA.4-LOCATION' && /does not record location conditions/.test(u.reason)))
})
test('endpoint sensors are read on Azure virtual machines only, never on workstations or firewalls', () => {
  const p = pack()
  put(p, 'EW.1', [
    { Scope: 'Azure VM', OSPlatform: 'WindowsServer2022', Devices: 10, Onboarded: 10, CanBeOnboarded: 0, SensorActive: 9 },
    { Scope: 'Azure VM', OSPlatform: 'Linux', Devices: 5, Onboarded: 5, CanBeOnboarded: 0, SensorActive: 5 },
    { Scope: 'Azure VM', OSPlatform: 'PAN-OS', Devices: 2, Onboarded: 2, CanBeOnboarded: 0, SensorActive: 0 },
    { Scope: 'Other device', OSPlatform: 'Windows11', Devices: 100, Onboarded: 100, CanBeOnboarded: 0, SensorActive: 40 },
    { Scope: 'Other device', OSPlatform: 'FortiOS', Devices: 3, Onboarded: 3, CanBeOnboarded: 0, SensorActive: 0 },
    { Scope: 'Other device', OSPlatform: 'SonicOS', Devices: 1, Onboarded: 1, CanBeOnboarded: 0, SensorActive: 0 }
  ])
  let m = build(p)
  let s = m.controls.find(c => c.label === 'Endpoint sensors active on onboarded Azure virtual machines')
  assert.deepEqual([s.good, s.total, s.mark, s.tier, s.group], [14, 15, 'E', 'foundational', 'Detection and response'])
  assert.match(s.note, /Workstations and network devices such as firewalls are not part of this measure/)
  assert.match(m.pillars[1].narrative, /93.3% of onboarded Azure virtual machine sensors active/)
  put(p, 'EW.1', [{ Scope: 'Other device', OSPlatform: 'Windows11', Devices: 100, Onboarded: 100, CanBeOnboarded: 0, SensorActive: 40 }])
  m = build(p)
  assert.ok(!m.controls.some(c => /^Endpoint sensors active/.test(c.label)), 'no Azure virtual machines means no row')
  assert.ok(m.review.some(r => /EW.1: no applicable resources/.test(r.text)))
  put(p, 'EW.1', [], 'UNAVAILABLE')
  assert.equal(build(p).controls.find(c => /^Endpoint sensors active/.test(c.label)).value, NULL_VALUE)
})
test('blob containers are graded on their own access level in every account, and readable ones stay in the presenter notes', () => {
  const p = pack()
  put(p, 'DP.1', [{ Accounts: 10, SecureTransfer: 10, MinTls12: 10, AnonymousBlobOff: 9, PublicNetworkOff: 2 }])
  put(p, 'DP.1-CONTAINERS', [{ Accounts: 10, AccountsUnread: 1, Containers: 200, PrivateContainers: 194, ExposedContainers: 2, AccountsExposed: 1 }])
  let m = build(p)
  const c = m.controls.find(x => x.id === 'DP.1-CONTAINERS')
  assert.deepEqual([c.label, c.good, c.total, c.mark, c.tier, c.group], ['Blob containers closed to anonymous access', 194, 200, 'E', 'defense', 'Network and boundary'])
  assert.equal(m.controls.find(x => x.label === 'Anonymous blob access disabled').tier, 'foundational', 'the account-level row stays foundational')
  assert.ok(m.presenter.some(n => n.title === 'Blob containers readable anonymously' && /2 blob containers are readable anonymously today in 1 storage account/.test(n.text)))
  assert.ok(m.review.some(n => n.title === 'Blob containers not read' && /1 storage account/.test(n.text)))
  assert.ok(!visible(m).includes('readable anonymously'))
  put(p, 'DP.1-CONTAINERS', [], 'EMPTY')
  assert.ok(!build(p).controls.some(x => x.id === 'DP.1-CONTAINERS'), 'no storage accounts, no row')
  delete p.results['DP.1-CONTAINERS']; p.manifest = p.manifest.filter(r => r.ResultId !== 'DP.1-CONTAINERS')
  assert.equal(build(p).controls.find(x => x.id === 'DP.1-CONTAINERS').value, NULL_VALUE, 'packs before collector 1.11.0 read (null)')
})
test('the standards edition lists every control row, and the endpoint rows read Azure virtual machines only', () => {
  const p = pack()
  assert.ok(build(p).controls.some(c => c.label === 'Azure virtual machines reporting to endpoint detection'))
  assert.ok(!build(p).controls.some(c => c.label === 'Endpoint detection and response deployed'), 'no fleet-wide device row since Oct 14, 2026')
  p.standard = true
  const m = build(p)
  assert.ok(m.controls.some(c => c.label === 'Azure virtual machines reporting to endpoint detection'))
  assert.ok(m.controls.every(c => c.note && !/No threat intelligence table recorded/.test(c.note)), 'every row describes its measure')
})
test('every device measure reads the Azure virtual machine rows only, so an older pack with workstation rows grades the same as a new one', () => {
  const p = pack()
  put(p, 'NB.8', [{ Scope: 'Azure VM', Devices: 87, Compliant: 85 }, { Scope: 'Other device', Devices: 2135, Compliant: 1901 }])
  put(p, 'EW.1', [{ Scope: 'Azure VM', OSPlatform: 'WindowsServer2022', Devices: 90, Onboarded: 87, CanBeOnboarded: 3, SensorActive: 87 }, { Scope: 'Other device', OSPlatform: 'Windows11', Devices: 2000, Onboarded: 1900, CanBeOnboarded: 100, SensorActive: 1800 }])
  put(p, 'EW.3', [{ Scope: 'Azure VM', ConfigurationName: 'Turn on real-time protection', Devices: 87, Compliant: 87 }, { Scope: 'Other device', ConfigurationName: 'Turn on real-time protection', Devices: 2000, Compliant: 1500 }])
  put(p, 'DR.5', [{ Scope: 'Azure VM', Onboarded: 87, Assessed: 80 }, { Scope: 'Other device', Onboarded: 1900, Assessed: 100 }])
  put(p, 'BKL.1', [{ Scope: 'Azure VM', Software: 'Operating system', VulnerabilitySeverityLevel: 'Critical', ExploitableCves: 2, Devices: 3 }, { Scope: 'Other device', Software: 'Operating system', VulnerabilitySeverityLevel: 'Critical', ExploitableCves: 40, Devices: 300 }])
  const m = build(p)
  const c = id => m.controls.find(x => x.id === id)
  assert.equal(c('NB.8').value, '85 of 87', 'network protection no longer reads 1,986 of 2,222')
  assert.equal(c('NB.8').label, 'Network protection in block mode on Azure virtual machines')
  const edr = m.controls.find(x => x.label === 'Azure virtual machines reporting to endpoint detection')
  assert.equal(edr.value, '87 of 90')
  assert.equal(c('EW.3').value, '87 of 87')
  assert.equal(c('DR.5').value, '80 of 87')
  assert.equal(m.criticalCves, 2)
  // A pack collected by 1.14.0 carries no Scope on some rows and no Other device rows at all.
  put(p, 'NB.8', [{ Scope: 'Azure VM', Devices: 87, Compliant: 85 }])
  assert.equal(build(p).controls.find(x => x.id === 'NB.8').value, '85 of 87')
})
test('the onboarding gaps explain the difference between the sensor figure and the onboarding figure, and a third-party product counts as protected', () => {
  const p = pack()
  put(p, 'EW.1', [{ Scope: 'Azure VM', OSPlatform: 'WindowsServer2022', Devices: 90, Onboarded: 87, CanBeOnboarded: 3, Unsupported: 0, InsufficientInfo: 0, SensorActive: 87 }])
  put(p, 'EW.1-GAPS', [
    { Reason: 'Covered by a third-party endpoint detection product', Product: 'CrowdStrike Falcon', Devices: 2, Eligible: true, Covered: true, Onboarded: 0, CanBeOnboarded: 2, NotSeen: 0, Other: 0 },
    { Reason: 'Network virtual appliance, cannot run a sensor', Product: '', Devices: 1, Eligible: false, Covered: false, Onboarded: 0, CanBeOnboarded: 1, NotSeen: 0, Other: 0 }
  ])
  put(p, 'EW.1-EDR', [{ VMs: 92, DefenderExtension: 87, ThirdPartyEdr: 2, Appliances: 1 }])
  let m = build(p)
  const edr = m.controls.find(c => c.label === 'Azure virtual machines reporting to endpoint detection')
  const sensors = m.controls.find(c => c.label === 'Endpoint sensors active on onboarded Azure virtual machines')
  assert.deepEqual([edr.good, edr.total, edr.mark], [89, 89, 'E'], 'the two CrowdStrike machines are protected and the appliance leaves the denominator')
  assert.deepEqual([sensors.good, sensors.total], [87, 87])
  for (const c of [edr, sensors]) assert.match(c.note, /3 Azure virtual machines are not reporting through an active Defender for Endpoint sensor\. 2 are covered by CrowdStrike Falcon and 1 is a network virtual appliance that cannot run a sensor\./)
  assert.match(m.pillars[1].narrative, /Endpoint detection covers 89 of 89 eligible Azure virtual machines/)
  assert.match(m.pillars[1].narrative, /2 are covered by CrowdStrike Falcon/)
  assert.ok(m.review.some(n => n.title === 'Azure virtual machines not reporting to Defender for Endpoint' && /confirm the product is licensed and reporting/.test(n.text)))
  assert.ok(m.review.some(n => n.title === 'Azure virtual machine inventory' && /92 Azure virtual machines in Resource Graph against 90 seen by Defender/.test(n.text)))
  assert.ok(!m.priorities.some(x => x.id === 'EW.1'))
  // A machine Defender never discovered, with no product on it, is a real gap and joins the denominator.
  put(p, 'EW.1-GAPS', [{ Reason: 'Not discovered by Defender for Endpoint', Product: '', Devices: 12, Eligible: true, Covered: false, Onboarded: 0, CanBeOnboarded: 0, NotSeen: 12, Other: 0 }, { Reason: 'Not onboarded, no endpoint detection found', Product: '', Devices: 3, Eligible: true, Covered: false, Onboarded: 0, CanBeOnboarded: 3, NotSeen: 0, Other: 0 }])
  m = build(p)
  const gap = m.controls.find(c => c.label === 'Azure virtual machines reporting to endpoint detection')
  assert.deepEqual([gap.good, gap.total, gap.mark], [87, 102, 'P'])
  assert.match(m.priorities.find(x => x.id === 'EW.1').evidence, /15 of 102 eligible Azure virtual machines are not yet reporting.*12 have never been discovered by Defender for Endpoint and 3 are not onboarded and carry no endpoint detection product/)
  assert.ok(m.hardening.some(h => h.label === 'Azure virtual machines pending endpoint onboarding' && h.value === 15))
  // Without the gap result the figures read as before, with no reconciliation sentence.
  put(p, 'EW.1-GAPS', [], 'UNAVAILABLE')
  m = build(p)
  const plain = m.controls.find(c => c.label === 'Azure virtual machines reporting to endpoint detection')
  assert.equal(plain.value, '87 of 90')
  assert.ok(!/not reporting through/.test(plain.note))
})
test('an empty onboarding gap result reads as every machine reporting only when the onboarding and sensor figures agree', () => {
  const p = pack()
  const every = /Every Azure virtual machine Defender for Endpoint has seen is onboarded with an active sensor/
  const endpointNotes = () => build(p).controls.filter(c => c.id === 'EW.1').map(c => c.note)
  put(p, 'EW.1', [{ Scope: 'Azure VM', OSPlatform: 'WindowsServer2022', Devices: 90, Onboarded: 90, CanBeOnboarded: 0, SensorActive: 90 }])
  put(p, 'EW.1-GAPS', [])
  assert.ok(endpointNotes().every(n => every.test(n)))
  put(p, 'EW.1', [{ Scope: 'Azure VM', OSPlatform: 'WindowsServer2022', Devices: 90, Onboarded: 89, CanBeOnboarded: 1, SensorActive: 89 }])
  assert.ok(endpointNotes().every(n => !every.test(n)), 'one machine is not onboarded, so the empty gap result claims nothing')
  put(p, 'EW.1', [{ Scope: 'Azure VM', OSPlatform: 'WindowsServer2022', Devices: 90, Onboarded: 90, CanBeOnboarded: 0, SensorActive: 85 }])
  assert.ok(endpointNotes().every(n => !every.test(n)), 'five sensors are not active, so the empty gap result claims nothing')
})
// Ratio readings at E that each leave resources out, as the independent review found them (endpoint detection 88 of
// 89, storage secure transfer 36 of 37, private containers 77 of 78, analytics rules 379 of 386), or with nothing
// left out when full is set.
const ABSOLUTE = /\b(every|all|none)\b/i
function readings(p, full = false) {
  const left = n => full ? 0 : n
  put(p, 'IA.1', [{ UserType: 'Member', UsersSignedIn: 194, UsersChallenged: 194 - left(14) }])
  put(p, 'EW.1', [{ Scope: 'Azure VM', OSPlatform: 'WindowsServer2022', Devices: 89, Onboarded: 89 - left(1), CanBeOnboarded: left(1), SensorActive: 89 - left(8) }])
  put(p, 'EW.1-GAPS', full ? [] : [
    { Reason: 'Onboarded, sensor not active', Product: '', Devices: 7, Eligible: true, Covered: false, Onboarded: 7, CanBeOnboarded: 0, NotSeen: 0, Other: 0 },
    { Reason: 'Not onboarded, no endpoint detection found', Product: '', Devices: 1, Eligible: true, Covered: false, Onboarded: 0, CanBeOnboarded: 1, NotSeen: 0, Other: 0 }
  ])
  put(p, 'DR.5', [{ Scope: 'Azure VM', Onboarded: 89 - left(1), Assessed: 89 - left(4) }])
  put(p, 'DP.4', [{ Resources: 40, WithEncryptionAtHost: 40 - left(2) }])
  put(p, 'DP.5b', [{ VmsWithoutBackup: left(2) }])
  put(p, 'EW.10', [{ Machines: 70, WithinCadence: 70 - left(2) }])
  put(p, 'NB.4', [{ Sites: 48, HttpsOnly: 48 - left(1) }])
  put(p, 'NB.1', [{ WorkloadSubnets: 30, Segmented: 30 - left(1) }])
  put(p, 'DP.1', [{ Accounts: 37, SecureTransfer: 37 - left(1), MinTls12: 37 - left(1), AnonymousBlobOff: 37 - left(1), PublicNetworkOff: 37 - left(2) }])
  put(p, 'DP.1-CONTAINERS', [{ Containers: 78, PrivateContainers: 78 - left(1), ExposedContainers: 0, AccountsExposed: 0, AccountsUnread: 0 }])
  put(p, 'DP.2', [{ Vaults: 20, SoftDelete: 20 - left(1), PurgeProtection: 20 - left(1), RbacAuth: 20 - left(1) }])
  put(p, 'DR.2', [{ Plan: 'VirtualMachines', ResourceType: 'microsoft.compute/virtualmachines', Resources: 200, Covered: 200 - left(5) }])
  put(p, 'DR.9', [{ Scope: 'All workspaces', Metric: 'Total rules', Value: 386 }, { Scope: 'All workspaces', Metric: 'Enabled rules', Value: 386 - left(7) }])
  put(p, 'DR.10', [{ Closed: 100, Documented: 100 - left(3) }])
}
const drop = (p, ...ids) => { for (const id of ids) { p.manifest = p.manifest.filter(r => r.ResultId !== id); delete p.results[id] } }
// OUT.1 with every alert closed and classified, so the disposition statement rests on DR.10 alone.
const settled = p => put(p, 'OUT.1', [{ Raised: 100, Closed: 100, Open: 0, TruePositive: 3, ClosedUnclassified: 0 }])
test('a reading at E that leaves resources out never reads every, all or none, and counts its exceptions', () => {
  const p = pack(); alerts(p); settled(p); readings(p)
  let m = build(p)
  const ratios = m.controls.filter(c => !c.boolean && c.pct !== null)
  assert.ok(ratios.length >= 15 && ratios.every(c => c.mark === 'E' && c.good < c.total), ratios.map(c => `${c.label} ${c.value}`).join(', '))
  for (const c of ratios) assert.equal(c.exceptions, c.total - c.good, c.label)
  for (const x of m.pillars) for (const t of [x.headline, x.headlineShort, x.narrative].filter(Boolean)) assert.ok(!ABSOLUTE.test(t), `${x.name}: ${t}`)
  // The headline leads with the ratio and the remainder, and the disposition statement takes the DR.10 ratio.
  assert.deepEqual(m.pillars.map(x => x.headline), [
    'Multifactor authentication covers 180 of 194 members at sign-in, with 14 remaining',
    'Endpoint detection covers 88 of 89 eligible Azure virtual machines, with 1 remaining',
    'Encryption in transit enforced on 47 of 48 published web apps, with 1 remaining',
    'Secure transfer is required on 36 of 37 storage accounts, with 1 remaining',
    '97 of 100 alerts closed in the last 30 days carry a documented disposition'
  ])
  const pillarOf = (model, name) => model.pillars.find(x => x.name === name)
  assert.match(pillarOf(m, 'Network and boundary').narrative, /47 of 48 published web apps enforce HTTPS\./)
  assert.match(pillarOf(m, 'Data protection').narrative, /^36 of 37 storage accounts require secure transfer\. 35 of 37 refuse public network access\. Soft delete protects 19 of 20 Key Vaults, and purge protection covers 19 of 20\. 38 of 40 virtual machines carry a backup policy\.$/)
  // EW.1-GAPS names the machines behind the remainder, so the endpoint row keeps the coverage sentence and the
  // reconciliation together, and offers a shorter headline a crowded slide can take before it cuts either.
  const endpoint = pillarOf(m, 'Endpoint and workload')
  assert.equal(endpoint.headlineShort, 'Endpoint detection covers 88 of 89 eligible Azure virtual machines')
  assert.match(endpoint.keep, /^Endpoint detection covers 88 of 89 eligible Azure virtual machines seen in the last 7 days, with 92% of onboarded Azure virtual machine sensors active\. 8 Azure virtual machines are not reporting through an active Defender for Endpoint sensor\. 7 are onboarded with a sensor that is not active and 1 is not onboarded and carries no endpoint detection product\.$/)
  assert.ok(endpoint.narrative.startsWith(endpoint.keep))
  assert.ok(m.pillars.every(x => x === endpoint || (!x.keep && !x.headlineShort)), 'only the endpoint row keeps sentences')
  // The fallback statements follow the same rule: encryption at host without EW.1, segmentation without NB.4,
  // soft delete without DP.1 and workload protection without an alert count.
  const q = pack(); readings(q); drop(q, 'EW.1', 'EW.1-GAPS', 'NB.4', 'DP.1')
  assert.deepEqual(build(q).pillars.slice(1).map(x => x.headline), [
    'Encryption at host is enabled on 38 of 40 virtual machines, with 2 remaining',
    'Segmentation covers 29 of 30 workload subnets, with 1 remaining',
    'Soft delete protects 19 of 20 Key Vaults, with 1 remaining',
    'Workload protection covers 195 of 200 eligible resources, with 5 remaining'
  ])
  // With nothing left out the same readings earn every and all, and no control counts an exception.
  const full = pack(); alerts(full); settled(full); readings(full, true)
  m = build(full)
  assert.ok(m.controls.every(c => !c.exceptions), m.controls.filter(c => c.exceptions).map(c => c.label).join(', '))
  assert.deepEqual(m.pillars.map(x => x.headline), ['Sign-ins are challenged for multifactor authentication', 'Every eligible Azure virtual machine reports to endpoint detection', 'Encryption in transit enforced on every published service', 'Data in transit and key material are protected', 'Every alert closed with a documented disposition'])
  assert.match(pillarOf(m, 'Network and boundary').narrative, /Every published web app enforces HTTPS\./)
  assert.match(pillarOf(m, 'Data protection').narrative, /^All storage accounts require secure transfer and refuse public network access\. Soft delete protects every Key Vault and purge protection is in force\. Every virtual machine carries a backup policy\.$/)
  assert.ok(!pillarOf(m, 'Endpoint and workload').keep, 'no machine is outside an active sensor')
  // Key material joins the data statement only when soft delete is complete as well.
  put(full, 'DP.2', [{ Vaults: 20, SoftDelete: 19, PurgeProtection: 19, RbacAuth: 20 }])
  assert.equal(pillarOf(build(full), 'Data protection').headline, 'Secure transfer is required on every storage account')
})
// The disposition statement says every alert only from a complete DR.10 reading of every workspace beside an OUT.1
// reading with no open alert and no unclassified closure. Open alerts lead with the closed and open counts from OUT.1.
// Otherwise a DR.10 reading of every workspace gives its own ratio with its window, and without one the statement
// leads with the triaged count. A partial DR.10 reading covers only the workspaces that answered, and the pillar
// cites OUT.1, so its ratio never leads the pillar, even when nothing it read is undocumented (Oct 16, 2026).
const renderHtml = data => {
  const nodes = {}
  const document = { body: { dataset: {} }, querySelectorAll: () => [], getElementById: id => nodes[id] || (nodes[id] = { textContent: id === 'report-data' ? JSON.stringify(data) : '', addEventListener() {} }) }
  vm.runInNewContext(fs.readFileSync(path.join(__dirname, '../report/report-render.js'), 'utf8'), { EbrReport: require('../report/report-model.js'), document, window: {} })
  return nodes.report.innerHTML
}
test('the detection statement says every alert only from a complete DR.10 reading and nothing open or unclassified', () => {
  const detection = p => build(p).pillars.find(x => x.name === 'Detection and response')
  const TRIAGED = '100 alerts triaged Nov 1, 2025 to Sep 30, 2026'
  const BOTH = 'OUT.1. Read Oct 8, 2026. DR.10. Read Oct 8, 2026.', OUT1 = 'OUT.1. Read Oct 8, 2026.'
  const p = pack(); alerts(p); settled(p); readings(p, true)
  // When DR.10 earns the statement, every alert or its own ratio, the source line cites it beside OUT.1.
  assert.deepEqual([detection(p).headline, detection(p).source], ['Every alert closed with a documented disposition', BOTH])
  assert.equal(detection(p).narrative.split('. ').slice(0, 2).join('. '), 'The SOC triaged 100 alerts Nov 1, 2025 to Sep 30, 2026. By collection, 100 were closed')
  const undocumented = pack(); alerts(undocumented); settled(undocumented); readings(undocumented, true)
  put(undocumented, 'DR.10', [{ Closed: 100, Documented: 97 }])
  assert.deepEqual([detection(undocumented).headline, detection(undocumented).source], ['97 of 100 alerts closed in the last 30 days carry a documented disposition', BOTH])
  const outcomes = [{ Open: 20, ClosedUnclassified: 5 }, { Open: 20, ClosedUnclassified: 0 }, { Open: 0, ClosedUnclassified: 5 }, { Open: 0, ClosedUnclassified: 0 }]
  const whole = [['complete', () => {}], ['undocumented', q => put(q, 'DR.10', [{ Closed: 100, Documented: 97 }])]]
  const unmeasured = [['missing', q => drop(q, 'DR.10')], ['unavailable', q => put(q, 'DR.10', [], 'UNAVAILABLE')], ['not readable', q => put(q, 'DR.10', [{ Closed: null, Documented: null }])],
    ['ungathered', q => put(q, 'DR.10', [{ Closed: 100, Documented: 101 }])], ['without closures', q => put(q, 'DR.10', [{ Closed: 0, Documented: 0 }])],
    ['partial with every closure documented', q => put(q, 'DR.10', [{ Closed: 100, Documented: 100 }], 'PARTIAL')], ['partial with closures undocumented', q => put(q, 'DR.10', [{ Closed: 100, Documented: 97 }], 'PARTIAL')]]
  for (const { Open, ClosedUnclassified } of outcomes) for (const [how, unset] of [...whole, ...unmeasured]) {
    const q = pack(); alerts(q); readings(q, true)
    put(q, 'OUT.1', [{ Raised: 100, Closed: 100 - Open, Open, TruePositive: 3, ClosedUnclassified }])
    unset(q)
    const m = build(q), row = m.pillars.find(x => x.name === 'Detection and response'), label = `DR.10 ${how}, ${Open} open, ${ClosedUnclassified} unclassified`
    const dr10 = whole.some(([w]) => w === how)
    const expected = Open > 0 ? [`${100 - Open} of 100 alerts closed, ${Open} open at collection`, OUT1]
      : !dr10 ? [TRIAGED, OUT1]
      : how === 'complete' && !ClosedUnclassified ? ['Every alert closed with a documented disposition', BOTH]
      : [`${how === 'complete' ? 100 : 97} of 100 alerts closed in the last 30 days carry a documented disposition`, BOTH]
    assert.deepEqual([row.headline, row.source], expected, `${label}: the headline's figure is the one the source line cites`)
    // Triage, closure, open status and classification are kept apart in the narrative.
    assert.ok(row.narrative.startsWith(`The SOC triaged 100 alerts Nov 1, 2025 to Sep 30, 2026. By collection, ${100 - Open} were closed.${Open ? ` ${Open} were pending client action, confirmation or continued investigation at collection.` : ''}`), `${label}: ${row.narrative}`)
    assert.equal(row.narrative.includes(`${ClosedUnclassified} closed alerts carry no recorded classification.`), ClosedUnclassified > 0, label)
    for (const t of [row.headline, row.narrative].filter(t => t !== 'Every alert closed with a documented disposition')) assert.ok(!ABSOLUTE.test(t) && !/;|\bincidents?\b|contain|impact|resolv/i.test(t), `${label}: ${t}`)
    // With an open alert or an unclassified closure no surface says every alert or worked to a disposition.
    if (Open || ClosedUnclassified) {
      const page = renderHtml(q)
      for (const text of [visible(m), page]) assert.ok(!/every alert|worked to a disposition/i.test(text), `${label}: ${text.match(/.{0,60}(every alert|worked to a disposition).{0,60}/i)?.[0]}`)
      assert.ok(!/alerts? resolved|been resolved/i.test(page), `${label}: the disposition panel says closed, never resolved`)
    }
  }
  // Beside the period's figures the page labels the DR.10 window, on the pillar statement and the register row, and
  // names the period's unclassified closures beside it.
  const windowed = pack(); alerts(windowed); readings(windowed, true)
  put(windowed, 'OUT.1', [{ Raised: 100, Closed: 100, Open: 0, TruePositive: 3, ClosedUnclassified: 5 }])
  const windowedPage = renderHtml(windowed)
  assert.ok(windowedPage.includes('<h4>100 of 100 alerts closed in the last 30 days carry a documented disposition</h4><p>The SOC triaged 100 alerts Nov 1, 2025 to Sep 30, 2026. By collection, 100 were closed.'), 'the pillar statement names the DR.10 window')
  assert.match(windowedPage, /<h4>100 of 100 alerts closed in the last 30 days carry a documented disposition<\/h4><p>[^<]*5 closed alerts carry no recorded classification\./)
  assert.match(windowedPage, /<h4>Alerts closed with a documented disposition<\/h4><p>Alerts closed in the last 30 days that carry a classification and a closing comment\.<\/p>/)
  assert.ok(windowedPage.includes('5 closed alerts carry no recorded classification.</p>'), 'the disposition panel names the unclassified closures')
  // OUT.1 reads each alert created in the period at its latest state at collection, so an alert open at the period's
  // end and closed before collection counts as closed: every status reads at or by collection, never at the period's
  // end or a reporting cutoff, and the panel never says an alert stayed open or closed inside the period.
  const later = pack(); alerts(later); readings(later, true)
  put(later, 'OUT.1', [{ Raised: 100, Closed: 100, Open: 0, TruePositive: 3, ClosedUnclassified: 1 }])
  const laterModel = build(later), laterPage = renderHtml(later)
  assert.ok(laterPage.includes('No alert created in the period was open at collection.'))
  for (const text of [visible(laterModel), laterPage]) assert.ok(!/reporting cutoff|remained open|at the period'?s? end|closed (this quarter|in the period|from )/i.test(text), text.match(/.{0,60}(reporting cutoff|remained open|period'?s? end|closed (this quarter|in the period|from )).{0,60}/i)?.[0])
  // The page carries the same statement the model earned.
  drop(p, 'DR.10')
  const page = renderHtml(p)
  assert.ok(page.includes(`<h4>${TRIAGED}</h4>`))
  assert.ok(!/Every alert/.test(page))
})
// OUT.1 holds the open count, never who holds each alert, so only a reviewed OpenAlertNote record bound to the period
// and accounting for every open alert splits it between the client and Atmosera (Oct 16, 2026).
test('open alerts split by owner only from a reviewed OpenAlertNote record', () => {
  const record = { AwaitingClient: 12, InProgress: 8, Reviewed: '2026-10-10', Reference: 'ZD 9900200', WindowStart: '2025-11-01', WindowEnd: '2026-09-30' }
  const withNote = note => { const p = pack(); alerts(p); p.parameters.TenantId = 't'; p.context = { ClientName: 'Example', TenantId: 't', OpenAlertNote: note }; return p }
  const COMBINED = '20 were pending client action, confirmation or continued investigation at collection.'
  const p = withNote(record), m = build(p), row = m.pillars.find(x => x.name === 'Detection and response')
  assert.equal(m.alerts.openSentence, '12 were awaiting client action or confirmation and 8 were still in progress with Atmosera at collection.')
  assert.ok(row.narrative.includes(`By collection, 80 were closed. ${m.alerts.openSentence}`), row.narrative)
  assert.equal(row.source, 'OUT.1. Read Oct 8, 2026. Reviewed open alert status ZD 9900200, Oct 10, 2026, from the reviewed context file.')
  assert.ok(m.presenter.some(n => n.title === 'Open alerts' && n.text.includes('ZD 9900200')))
  const page = renderHtml(p)
  assert.ok(page.includes('20 alerts were open at collection. Of these, 12 were awaiting client action or confirmation and 8 were still in progress with Atmosera.'))
  assert.ok(page.includes('Reviewed open alert status ZD 9900200'))
  const single = build(withNote({ ...record, AwaitingClient: 0, InProgress: 20 }))
  assert.equal(single.alerts.openSentence, '20 were still in progress with Atmosera at collection.')
  // A record that fails a check is omitted with a note naming why, and the surfaces keep the combined sentence.
  for (const [why, bad, reason] of [['a count that does not add up', { ...record, InProgress: 7 }, /accounts for 19 open alerts and the pack holds 20/], ['another period', { ...record, WindowStart: '2025-08-01', WindowEnd: '2025-10-31' }, /covers Aug 1 to Oct 31, 2025/],
    ['a review before the period ended', { ...record, Reviewed: '2026-09-01' }, /before the alert period ended/], ['no reference', { ...record, Reference: '' }, /lacks/], ['a negative count', { ...record, AwaitingClient: -1, InProgress: 21 }, /lacks/], ['free text', '12 with the client', /lacks/]]) {
    const q = withNote(bad), n = build(q)
    assert.equal(n.alerts.openSplit, undefined, why)
    assert.equal(n.alerts.openSentence, COMBINED, why)
    assert.ok(n.review.some(r => r.title === 'Open alert status needs review' && reason.test(r.text)), why)
    assert.ok(!renderHtml(q).includes('still in progress with Atmosera'), why)
  }
})
test('the controls page names the exceptions of a control at E beside its figure', () => {
  const html = data => {
    const nodes = {}
    const document = { body: { dataset: {} }, querySelectorAll: () => [], getElementById: id => nodes[id] || (nodes[id] = { textContent: id === 'report-data' ? JSON.stringify(data) : '', addEventListener() {} }) }
    vm.runInNewContext(fs.readFileSync(path.join(__dirname, '../report/report-render.js'), 'utf8'), { EbrReport: require('../report/report-model.js'), document, window: {} })
    return nodes.report.innerHTML
  }
  const p = pack(); readings(p)
  const near = html(p)
  assert.ok(near.includes('title="Enforced, 1 exception">E</span><div class="control-text"><h4>Azure virtual machines reporting to endpoint detection</h4>'), 'the mark names the exception')
  assert.match(near, /<h4>Azure virtual machines reporting to endpoint detection<\/h4>[\s\S]*?<strong>88 of 89<\/strong>[\s\S]*?<span class="exceptions">1 exception<\/span>/)
  assert.match(near, /<strong>379 of 386<\/strong>[\s\S]*?<span class="exceptions">7 exceptions<\/span>/)
  assert.ok(near.includes('shows how many as exceptions'), 'the legend explains the count')
  const full = pack(); readings(full, true)
  assert.ok(!html(full).includes('class="exceptions"'), 'a complete reading carries no exception line')
})
test('MFA at sign-in and admin portal MFA read In force from the Conditional Access policy, with the sign-in ratio in the note', () => {
  const p = pack()
  put(p, 'IA.1', [{ UserType: 'Member', UsersSignedIn: 200, UsersChallenged: 150 }])
  put(p, 'IA.1-ADMINPORTAL', [{ UserType: 'Member', Users: 20, UsersChallenged: 19, SignIns: 300, MfaSignIns: 290 }])
  const flows = state => [
    { Flow: 'MFA at sign-in', Control: 'IA.1', PolicyRead: true, PolicySource: 'Raw', PolicyState: state, EnforcedPolicies: state === 'Enforced' ? 1 : 0, ExcludedIdentities: 2, DetailRead: false },
    { Flow: 'Admin portals', Control: 'IA.1-ADMINPORTAL', PolicyRead: true, PolicySource: 'Raw', PolicyState: state, EnforcedPolicies: state === 'Enforced' ? 1 : 0, ExcludedIdentities: 0, DetailRead: false }
  ]
  p.results['IA.8-CA'] = flows('Enforced')
  let m = build(p)
  const mfa = m.controls.find(c => c.id === 'IA.1'), portal = m.controls.find(c => c.id === 'IA.1-ADMINPORTAL')
  assert.deepEqual([mfa.value, mfa.mark, mfa.boolean], ['In force', 'E', true])
  assert.match(mfa.note, /An enabled Conditional Access policy requires multifactor authentication on every application for all users\. 150 of 200 members who signed in over the last 30 days satisfied it\./)
  assert.deepEqual([portal.value, portal.mark], ['In force', 'E'])
  assert.match(portal.note, /requires multifactor authentication on the Microsoft admin portals for administrators\. 19 of 20 members who signed in to a Microsoft admin portal/)
  assert.ok(m.presenter.some(n => n.title === 'MFA at sign-in' && /reads in force from the Conditional Access policy\. The sign-in logs show 150 of 200 members/.test(n.text)), 'a ratio below E is explained to the presenter, never on the client page')
  assert.ok(!m.priorities.some(x => x.id === 'IA.1'), 'a policy in force is not a priority')
  assert.ok(!m.hardening.some(h => h.id === 'IA.1'), 'and not a hardening count')
  assert.match(m.pillars[0].narrative, /^Conditional Access requires multifactor authentication for every user on every application\. 75% of members who signed in over the last 30 days satisfied it\./)
  assert.equal(m.pillars[0].measure.label, 'Users challenged for MFA at sign-in')
  assert.equal(m.pillars[0].measure.pct, 75)
  // A scoped policy with at least half of the evaluated members on MFA reads Mostly enforced, marked P with the
  // ratio behind it, and the sign-in gap still becomes the priority evidence (Oct 14, 2026).
  p.results['IA.8-CA'] = flows('Scoped')
  m = build(p)
  const scoped = m.controls.find(c => c.id === 'IA.1')
  assert.deepEqual([scoped.value, scoped.mark, scoped.boolean, scoped.pct, scoped.good, scoped.total, scoped.ratioText], ['Mostly enforced', 'P', true, 75, 150, 200, '150 of 200'])
  assert.match(m.priorities.find(x => x.id === 'IA.1').evidence, /applies to selected users, applications or conditions only\. 50 of 200 members showed no multifactor authentication/)
  // The hardening count is written against the same members as the control, so the executive summary reads
  // "50 of 200" beside a control reading "150 of 200".
  assert.ok(m.hardening.some(h => h.id === 'IA.1' && h.value === 50 && h.of === 200))
  assert.deepEqual(m.tiers.hardening.find(r => r.id === 'IA.1'), { label: 'Members who signed in without MFA, last 30 days', value: '50 of 200', id: 'IA.1' })
  assert.ok(m.presenter.some(n => n.title === 'MFA at sign-in' && /reads mostly enforced from the Conditional Access policy, because the enabled policy applies to selected users, applications or conditions only and the sign-in ratio/.test(n.text)))
  assert.deepEqual([m.controls.find(c => c.id === 'IA.1-ADMINPORTAL').value, m.controls.find(c => c.id === 'IA.1-ADMINPORTAL').ratioText], ['Mostly enforced', '19 of 20'])
  assert.equal(m.pillars[0].headline, 'Multifactor authentication covers most sign-ins, with full coverage sequenced')
  assert.ok(m.tierSummary.foundational.enforced < m.tierSummary.foundational.measured, 'mostly enforced is not counted as enforced')
  // The policy caps the grade at P however high the ratio: 95 percent under a scoped policy is still Mostly enforced.
  put(p, 'IA.1', [{ UserType: 'Member', UsersSignedIn: 200, UsersChallenged: 190 }])
  assert.deepEqual([build(p).controls.find(c => c.id === 'IA.1').value, build(p).controls.find(c => c.id === 'IA.1').mark, build(p).controls.find(c => c.id === 'IA.1').pct], ['Mostly enforced', 'P', 95])
  // Below half, a scoped policy still reads Not in force. Report-only and absent policies do too.
  put(p, 'IA.1', [{ UserType: 'Member', UsersSignedIn: 200, UsersChallenged: 90 }])
  m = build(p)
  assert.deepEqual([m.controls.find(c => c.id === 'IA.1').value, m.controls.find(c => c.id === 'IA.1').mark, m.controls.find(c => c.id === 'IA.1').ratioText], ['Not in force', 'N', undefined])
  put(p, 'IA.1', [{ UserType: 'Member', UsersSignedIn: 200, UsersChallenged: 150 }])
  for (const state of ['Report-only', 'None']) { p.results['IA.8-CA'] = flows(state); assert.equal(build(p).controls.find(c => c.id === 'IA.1').value, 'Not in force', state) }
  // The note names how the policy is scoped when the evaluator recorded it, and the grade still rests on the ratio.
  p.results['IA.8-CA'] = flows('Scoped').map(f => ({ ...f, ScopeReason: 'Conditions' }))
  let c = build(p).controls.find(x => x.id === 'IA.1')
  assert.deepEqual([c.value, c.mark], ['Mostly enforced', 'P'])
  assert.match(c.note, /^The enabled Conditional Access policy that requires multifactor authentication on every application applies under selected conditions only, such as a platform, risk level, device filter or location\. 150 of 200/)
  assert.ok(build(p).presenter.some(n => n.title === 'MFA at sign-in' && /because the enabled policy applies under selected conditions only and the sign-in ratio/.test(n.text)), 'the presenter note names the same scoping')
  p.results['IA.8-CA'] = flows('Scoped').map(f => ({ ...f, ScopeReason: 'Users' }))
  c = build(p).controls.find(x => x.id === 'IA.1')
  assert.match(c.note, /^The enabled Conditional Access policy that requires multifactor authentication on every application applies to selected users only\. 150 of 200/)
  // A policy scoped to selected applications never reads as requiring MFA on every application.
  p.results['IA.8-CA'] = flows('Scoped').map(f => ({ ...f, ScopeReason: 'Applications' }))
  c = build(p).controls.find(x => x.id === 'IA.1')
  assert.match(c.note, /^The enabled Conditional Access policy that requires multifactor authentication applies to selected applications only\. 150 of 200/)
  assert.ok(!/every application/.test(c.note))
  assert.ok(!/every application/.test(build(p).priorities.find(x => x.id === 'IA.1').evidence))
  assert.ok(build(p).presenter.some(n => n.title === 'MFA at sign-in' && /because the enabled policy applies to selected applications only/.test(n.text)))
  p.results['IA.8-CA'] = flows('Scoped').map(f => ({ ...f, ScopeReason: 'UsersAndApplications' }))
  assert.match(build(p).controls.find(x => x.id === 'IA.1').note, /that requires multifactor authentication applies to selected users and selected applications only\./)
  // Without a policy inventory the sign-in ratio grades the control as before.
  delete p.results['IA.8-CA']
  m = build(p)
  const ratio = m.controls.find(c => c.id === 'IA.1')
  assert.deepEqual([ratio.value, ratio.mark, ratio.boolean], ['150 of 200', 'P', undefined])
  assert.equal(m.controls.find(c => c.id === 'IA.1-ADMINPORTAL').value, '19 of 20')
})
test('workload protection names the resource types outside Standard plan coverage', () => {
  const p = pack()
  put(p, 'DR.2', [{ Plan: 'AI', ResourceType: 'microsoft.cognitiveservices/accounts', Resources: 24, Covered: 0 }, { Plan: 'KeyVaults', ResourceType: 'microsoft.keyvault/vaults', Resources: 9, Covered: 9 }, { Plan: 'VirtualMachines', ResourceType: 'microsoft.compute/virtualmachines', Resources: 21, Covered: 21 }, { Plan: 'VirtualMachines', ResourceType: 'microsoft.hybridcompute/machines', Resources: 72, Covered: 70 }, { Plan: 'StorageAccounts', ResourceType: 'microsoft.storage/storageaccounts', Resources: 1, Covered: 0 }])
  const m = build(p)
  const plan = m.controls.find(c => c.id === 'DR.2')
  assert.equal(plan.value, '100 of 127')
  assert.equal(plan.gap, '24 AI services, 2 virtual machine and 1 storage account not covered')
  assert.match(plan.note, /read from the subscription plan configuration\. Not covered: 24 AI services resources, 2 virtual machine resources and 1 storage account resource\.$/)
  put(p, 'DR.2', [{ Plan: 'KeyVaults', ResourceType: 'microsoft.keyvault/vaults', Resources: 9, Covered: 9 }])
  const full = build(p).controls.find(c => c.id === 'DR.2')
  assert.equal(full.gap, undefined); assert.ok(!/Not covered/.test(full.note))
})
test('Arc-enabled servers are named in the endpoint notes and reconcile the inventory review note', () => {
  const p = pack()
  put(p, 'EW.1', [{ Scope: 'Azure VM', OSPlatform: 'WindowsServer2022', Devices: 92, Onboarded: 90, CanBeOnboarded: 2, Unsupported: 0, InsufficientInfo: 0, SensorActive: 90 }])
  put(p, 'EW.1-EDR', [{ VMs: 21, DefenderExtension: 15, ThirdPartyEdr: 0, Appliances: 0 }])
  put(p, 'DR.2', [{ Plan: 'VirtualMachines', ResourceType: 'microsoft.compute/virtualmachines', Resources: 21, Covered: 21 }, { Plan: 'VirtualMachines', ResourceType: 'microsoft.hybridcompute/machines', Resources: 72, Covered: 72 }])
  const m = build(p)
  assert.match(m.controls.find(c => c.label === 'Azure virtual machines reporting to endpoint detection').note, /Azure Arc-enabled servers carry an Azure resource ID, so those Defender for Endpoint has seen count here beside the native virtual machines\. Resource Graph lists 72 Arc-enabled servers at collection\./)
  const review = m.review.find(n => n.title === 'Azure virtual machine inventory')
  assert.match(review.text, /^EW\.1-EDR: 21 Azure virtual machines in Resource Graph against 92 seen by Defender for Endpoint/)
  assert.match(review.text, /Resource Graph also lists 72 Azure Arc-enabled servers \(DR\.2\), which carry an Azure resource ID and count in the Defender scope but are not in the EW\.1-EDR inventory, so the Arc share of the difference is not reconciled machine by machine\. EW\.1-GAPS explains the native virtual machines/)
  p.results['EW.1'][0].Devices = 21
  assert.ok(!build(p).review.some(n => n.title === 'Azure virtual machine inventory'), 'an inventory that reconciles raises no note')
})
test('the Defender for Cloud score movement is measured to the current score, so the points and the percentage reconcile', () => {
  const p = pack()
  put(p, 'POS.1', [{ Current: 132.75, Max: 232, Percent: 57.2, Subscriptions: 1 }])
  put(p, 'POS.7', [{ Month: '2026-07-01', Current: 123.82, Max: 238, Percent: 52 }, { Month: '2026-08-01', Current: 114.09, Max: 232, Percent: 49.2 }, { Month: '2026-10-01', Current: 133.32, Max: 232, Percent: 57.5 }])
  const m = build(p)
  assert.equal(m.cloudScore.value, 57.2)
  assert.deepEqual(m.cloudScore.delta, { points: 5.2, since: 'Jul 2026', from: 52 })
  p.results['POS.1'][0].Current = 120
  assert.equal(build(p).cloudScore.delta, null, 'a current score below the first month shows no gain')
  // The export can lag the current reading: a last trend point below the first month does not hide a real gain.
  p.results['POS.1'][0].Current = 132.75
  p.results['POS.7'][2].Percent = 50
  assert.deepEqual(build(p).cloudScore.delta, { points: 5.2, since: 'Jul 2026', from: 52 })
})
test('the benchmark meter reads the Microsoft cloud security benchmark alone when a preview edition or another standard is assigned too', () => {
  const p = pack()
  put(p, 'POS.5', [{ Standard: 'Azure-CSPM', Passed: 0, Failed: 1 }, { Standard: 'Microsoft-cloud-security-benchmark', Passed: 44, Failed: 18 }, { Standard: 'Microsoft-cloud-security-benchmark', Passed: 40, Failed: 23 }, { Standard: 'Microsoft-cloud-security-benchmark-v2-(Preview)', Passed: 29, Failed: 14 }])
  const m = build(p)
  assert.deepEqual([m.posture.benchmark.passed, m.posture.benchmark.total], [84, 125])
  put(p, 'POS.5', [{ Standard: 'Custom', Passed: 3, Failed: 1 }, { Standard: 'Other', Passed: 2, Failed: 2 }])
  assert.equal(build(p).posture.benchmark, null, 'named standards that are not the benchmark never stand in for it')
  put(p, 'POS.5', [{ Passed: 3, Failed: 1 }, { Passed: 2, Failed: 2 }])
  assert.deepEqual([build(p).posture.benchmark.passed, build(p).posture.benchmark.total], [5, 8], 'legacy rows with no standard name count as a whole')
  // A tenant on the v2 rollout alone reports that edition, never the CSPM scaffold or a custom standard beside it.
  put(p, 'POS.5', [{ Standard: 'Azure-CSPM', Passed: 0, Failed: 1 }, { Standard: 'Custom', Passed: 3, Failed: 1 }, { Standard: 'Microsoft-cloud-security-benchmark-v2-(Preview)', Passed: 29, Failed: 14 }, { Standard: 'Microsoft-cloud-security-benchmark-v2-(Preview)', Passed: 17, Failed: 25 }])
  assert.deepEqual([build(p).posture.benchmark.passed, build(p).posture.benchmark.total], [46, 85], 'the versioned edition is the benchmark')
  put(p, 'POS.5', [{ Standard: 'Microsoft-cloud-security-benchmark-v2', Passed: 30, Failed: 10 }, { Standard: 'Microsoft-cloud-security-benchmark-v3-(Preview)', Passed: 5, Failed: 35 }])
  assert.deepEqual([build(p).posture.benchmark.passed, build(p).posture.benchmark.total], [30, 40], 'a released edition beats a preview')
  put(p, 'POS.5', [{ Standard: 'Microsoft-cloud-security-benchmark-v9', Passed: 1, Failed: 9 }, { Standard: 'Microsoft-cloud-security-benchmark-v10', Passed: 8, Failed: 2 }])
  assert.deepEqual([build(p).posture.benchmark.passed, build(p).posture.benchmark.total], [8, 10], 'editions compare by version number, not as text')
})
test('a tenant that is not onboarded to Defender for Identity reads Not in force and needs a license, never read access', () => {
  const p = pack()
  p.manifest.push({ ResultId: 'DR.11', Status: 'UNAVAILABLE', Rows: 0, ReadTimeUtc: '2026-10-08T10:00:00Z', AccessGap: false, NotOnboarded: true })
  // Without positive evidence of domain controllers the control stays ungathered: NB.10 reads Azure virtual
  // machines only and DR.4 needs Defender for Identity telemetry, so an empty read proves nothing.
  let m = build(p)
  let c = m.controls.find(x => x.id === 'DR.11')
  assert.deepEqual([c.value, c.measured], ['(null)', false])
  assert.ok(m.unmeasured.some(u => u.id === 'DR.11' && /holds no evidence of domain controllers/.test(u.reason)))
  put(p, 'NB.10', [], 'EMPTY'); put(p, 'DR.4', [], 'EMPTY')
  m = build(p)
  c = m.controls.find(x => x.id === 'DR.11')
  assert.deepEqual([c.value, c.measured, c.na], ['(null)', false, undefined], 'empty reads are not proof of a cloud-only tenant')
  // Domain controllers in Azure (NB.10) make it a gap that needs a license.
  put(p, 'NB.10', [{ Scope: 'Azure VM', Devices: 3, Compliant: 0 }])
  m = build(p)
  c = m.controls.find(x => x.id === 'DR.11')
  assert.deepEqual([c.value, c.mark, c.tier, c.needsLicense], ['Not in force', 'N', 'foundational', true])
  assert.match(c.note, /not onboarded to Microsoft Defender for Identity/)
  assert.ok(!m.unmeasured.some(u => u.id === 'DR.11'))
  p.manifest.find(r => r.ResultId === 'DR.11').NotOnboarded = false
  assert.equal(build(p).controls.find(x => x.id === 'DR.11').value, '(null)', 'a plain read failure stays ungathered')
})
test('the patch cadence note states how many machines a tag left out', () => {
  const p = pack()
  put(p, 'EW.10', [{ Machines: 40, WithinCadence: 38, OverduePatches: 4, AssessedWithin7d: 40 }])
  put(p, 'EW.10-EXCLUDED', [{ Machines: 5 }])
  const m = build(p)
  assert.match(m.controls.find(c => c.id === 'EW.10').note, /5 machines are left out because a tag records patching as waived or client owned\./)
  assert.ok(m.review.some(n => n.title === 'Patch measures' && /EW\.10-EXCLUDED: 5 machines/.test(n.text)))
  put(p, 'EW.10-EXCLUDED', [], 'EMPTY')
  assert.ok(!/left out because a tag/.test(build(p).controls.find(c => c.id === 'EW.10').note))
})
// Shook (shb-com), Oct 13, 2026: the member view of Q3 in docs/Federated MFA Evaluation.md.
const federatedMember = { UserType: 'Member', UsersSignedIn: 1414, UsersChallenged: 563, UsersAlwaysMfa: 1, UsersExternalMfa: 563, UsersEntraMfa: 60, MfaAtLeastOnce: 563, MfaEveryAppSignIn: 1, CoveredEveryAppSignIn: 5, FederatedMfaAtLeastOnce: 563, FederatedWithoutMfa: 2, NoMfaOnlyUnevaluated: 550, MfaSessionLinkedOnly: 31 }
test('in a federated tenant IA.1 leaves members with only unevaluated sessions out of the grade and explains why in the presenter notes', () => {
  const p = pack()
  put(p, 'IA.1', [federatedMember, { UserType: 'Guest', UsersSignedIn: 668, UsersChallenged: 548, NoMfaOnlyUnevaluated: 20 }])
  put(p, 'IA.1-FEDERATION', [{ FederatedDomains: 4, ConfigsRead: 1, Provider: 'Okta', MfaBehavior: 'enforceMfaByFederatedIdp', MfaBehaviorUnset: 0 }])
  put(p, 'IA.1-ADMINPORTAL', [{ UserType: 'Member', Users: 60, UsersChallenged: 50, UsersAlwaysMfa: 40, SignIns: 900, MfaSignIns: 700, FederatedMfaAtLeastOnce: 30, FederatedWithoutMfa: 0, NoMfaOnlyUnevaluated: 5, NotEvaluatedSignIns: 120 }])
  const m = build(p)
  const mfa = m.controls.find(c => c.id === 'IA.1')
  assert.deepEqual([mfa.good, mfa.total, mfa.pct, mfa.mark], [563, 864, 65.2, 'P'], 'not evaluated is not missing MFA')
  assert.match(mfa.note, /out of the members whose sign-ins could be evaluated/)
  assert.match(mfa.note, /recorded as not evaluated, not as missing multifactor authentication/)
  assert.equal(mfa.population, 'Members whose sign-ins in the last 30 days could be evaluated.')
  const portal = m.controls.find(c => c.id === 'IA.1-ADMINPORTAL')
  assert.deepEqual([portal.good, portal.total], [50, 55])
  const note = m.presenter.find(n => n.title === 'Federated sign-in and MFA')
  assert.ok(note, 'presenter note for the federated tenant')
  assert.match(note.text, /^The tenant is federated with Okta \(4 domains\)\./)
  assert.match(note.text, /550 of 1,414 members signed in only through such sessions in the last 30 days and are left out of the grade\. 31 members count as covered only by inference from an earlier MFA sign-in in the same session/)
  assert.match(note.text, /At the admin portals, 5 members were left out the same way/)
  assert.match(note.text, /563 members showed MFA asserted by the identity provider/)
  assert.match(note.text, /2 members signed in through the identity provider without an MFA assertion/)
  assert.match(note.text, /enforceMfaByFederatedIdp/)
  assert.match(note.text, /report-only Conditional Access policy with the Require multifactor authentication grant/)
  const priority = m.priorities.find(x => x.id === 'IA.1')
  assert.match(priority.evidence, /^301 of 864 members whose sign-ins could be evaluated/)
  assert.match(priority.action, /report-only Conditional Access policy/)
  const text = visible(m) + JSON.stringify(m.presenter)
  assert.ok(!/[;→←⇒]/.test(text), 'no semicolons or arrows in client copy or presenter notes')
  assert.ok(!visible(m).includes('550'), 'the not evaluated count stays in the presenter notes')
  assert.ok(!/inference/.test(visible(m)), 'the inferred count stays in the presenter notes')
})
test('a managed tenant, a federated tenant without the Graph read and older packs keep their readings', () => {
  const p = pack()
  put(p, 'IA.1', [federatedMember])
  put(p, 'IA.1-FEDERATION', [], 'EMPTY')
  let m = build(p)
  let mfa = m.controls.find(c => c.id === 'IA.1')
  assert.deepEqual([mfa.good, mfa.total], [563, 1414], 'no federated domain, no exclusion')
  assert.match(mfa.note, /Windows logon and device registration are left out/)
  assert.ok(!m.presenter.some(n => n.title === 'Federated sign-in and MFA'))
  assert.equal(m.presenter.find(n => n.title === 'MFA inferred from the session').text, '31 members count as covered only by inference from an earlier MFA sign-in in the same session, not from MFA recorded on their own sign-ins.')
  put(p, 'IA.1-FEDERATION', [], 'UNAVAILABLE')
  m = build(p)
  assert.equal(m.controls.find(c => c.id === 'IA.1').total, 864, 'federated sign-ins in IA.1 stand in for the Graph read')
  assert.match(m.presenter.find(n => n.title === 'Federated sign-in and MFA').text, /as the federated sign-ins in IA.1 show\. The federated domains themselves could not be read\./)
  put(p, 'IA.1', [{ ...federatedMember, UsersSignedIn: 550, UsersChallenged: 0, NoMfaOnlyUnevaluated: 550 }])
  put(p, 'IA.1-FEDERATION', [{ FederatedDomains: 1, ConfigsRead: 1, Provider: 'Other', MfaBehavior: '' }])
  m = build(p)
  mfa = m.controls.find(c => c.id === 'IA.1')
  assert.equal(mfa.value, NA_VALUE, 'every member unevaluated is no evidence either way')
  assert.match(m.presenter.find(n => n.title === 'Federated sign-in and MFA').text, /^The tenant is federated \(1 domain\)\./)
  // Packs collected before 1.12.0: no NoMfaOnlyUnevaluated column, so the grade reads as before.
  const old = pack()
  put(old, 'IA.1', [{ UserType: 'Member', UsersSignedIn: 1422, UsersChallenged: 600, UsersAlwaysMfa: 98, UsersExternalMfa: 563, UsersEntraMfa: 96 }])
  m = build(old)
  mfa = m.controls.find(c => c.id === 'IA.1')
  assert.deepEqual([mfa.good, mfa.total], [600, 1422])
  assert.match(m.presenter.find(n => n.title === 'MFA coverage query').text, /collected before collector 1\.12\.0/)
  assert.ok(!m.presenter.some(n => n.title === 'Federated sign-in and MFA'))
  put(old, 'IA.1', [{ UserType: 'Member', UsersSignedIn: 100, UsersChallenged: 85 }])
  assert.match(build(old).presenter.find(n => n.title === 'MFA coverage query').text, /before IA.1 recognised MFA satisfied by external identity provider claims/)
})
test('confirmed threat examples are grouped by title, tied to an attack stage, ordered by severity and capped at five', () => {
  const p = pack(); alerts(p)
  const rowsOut = [
    ...Array.from({ length: 8 }, (_, i) => threat('Log4j vulnerability exploit aka Log4Shell IP IOC', 'High', 'CommandAndControl', `2026-0${i < 4 ? 8 : 9}-1${i}`)),
    threat('Password spray attack against Microsoft Entra ID application', 'Medium', 'CredentialAccess', '2026-07-28'),
    threat('Password spray attack against Microsoft Entra ID application', 'Medium', 'CredentialAccess', '2026-08-22'),
    threat('User account compromised by device code phishing (attack disruption)', 'High', 'CredentialAccess,InitialAccess,Persistence,PrivilegeEscalation,DefenseEvasion', '2026-09-16'),
    threat('Multi-stage incident involving Initial access and Lateral movement', 'Low', 'LateralMovement,InitialAccess', '2025-12-30'),
    threat('Multi-stage incident involving Initial access and Lateral movement', 'Medium', 'InitialAccess', '2026-01-04'),
    threat('Rare A', 'Low', 'Discovery', '2026-05-01'), threat('Rare B', 'Low', 'Discovery', '2026-05-02'),
    threat('Title withheld', 'High', 'Collection', '2026-08-01'),
    // The builder's fail-closed row, when screening throws: withheld, never an operational true positive.
    { Threat: 'Title withheld', Severity: 'High', Tactics: '', Created: '', ExfilOrImpactTactic: false },
    // Staged rows with no title or no day are withheld too, so every row is an example, withheld or operational.
    threat('', 'Medium', 'Execution', '2026-06-01'), threat('Suspicious sign-in from a rare location', 'High', 'InitialAccess', ''),
    threat('', 'Low', '', '2026-09-15')
  ]
  put(p, 'OUT.4', rowsOut)
  const m = build(p)
  assert.deepEqual(m.threats.examples.map(t => [t.title, t.alerts, t.severity]), [
    ['Log4j vulnerability exploit aka Log4Shell IP IOC', 8, 'High'],
    ['User account compromised by device code phishing (attack disruption)', 1, 'High'],
    ['Password spray attack against Microsoft Entra ID application', 2, 'Medium'],
    ['Multi-stage alert involving Initial access and Lateral movement', 2, 'Medium'],
    ['Rare B', 1, 'Low']
  ])
  assert.deepEqual([m.threats.more, m.threats.moreAlerts], [1, 1])
  const ex = Object.fromEntries(m.threats.examples.map(t => [t.title, t]))
  assert.equal(ex['Log4j vulnerability exploit aka Log4Shell IP IOC'].stage, 'Command and control')
  assert.equal(ex['Log4j vulnerability exploit aka Log4Shell IP IOC'].when, 'August to September 2026')
  assert.equal(ex['Password spray attack against Microsoft Entra ID application'].when, 'July to August 2026')
  assert.equal(ex['User account compromised by device code phishing (attack disruption)'].stage, 'Initial access, Persistence, plus 3 more stages')
  assert.equal(ex['User account compromised by device code phishing (attack disruption)'].when, 'September 2026')
  assert.equal(ex['Multi-stage alert involving Initial access and Lateral movement'].stage, 'Initial access, Lateral movement')
  assert.equal(ex['Multi-stage alert involving Initial access and Lateral movement'].when, 'December 2025 to January 2026')
  assert.ok(m.presenter.some(n => n.title === 'Confirmed threat titles withheld' && /^4 confirmed alerts are left out of the examples because their titles may identify an account, address, host or other internal detail, could not be screened, or carry no title or date\. The tickets and the pack's OUT\.4 result carry the detail\.$/.test(n.text)))
  assert.ok(m.presenter.some(n => n.title === 'Operational true positives' && /^1 confirmed alert carries no attack stage/.test(n.text)))
  const examplesNote = m.presenter.find(n => n.title === 'Confirmed threat examples').text
  assert.match(examplesNote, /^The examples use alert titles as Sentinel recorded them, with incident written as alert\. Titles that carry an email address, IP address, host or domain name, path, GUID, ticket reference or machine-style name are withheld automatically\. Check that no title shown names a person, account or machine, or implies containment, before the review\./)
  assert.match(examplesNote, /The table shows 14 confirmed alerts in 5 groups\. 1 more sits in 1 further group\.$/, 'examples, withheld and operational rows reconcile with the 20 rows in OUT.4')
  assert.ok(!/\bincidents?\b/i.test(JSON.stringify(m.threats)), 'titles follow the alerts vocabulary')
})
test('threat examples are omitted when there are none, when alerts are withheld, or when the report data predates them', () => {
  let p = pack(); alerts(p)
  put(p, 'OUT.4', [threat('', 'Low', '', '2026-09-15')])
  assert.equal(build(p).threats, null)
  p = pack(); alerts(p, { duplicates: 3 })
  put(p, 'OUT.4', [threat('Password spray', 'Medium', 'CredentialAccess', '2026-08-22')])
  assert.equal(build(p).threats, null, 'duplicate alerts withhold every alert figure')
  p = pack(); alerts(p)
  put(p, 'OUT.4', [{ Severity: 'High', ExfilOrImpactTactic: false }])
  const m = build(p)
  assert.equal(m.threats, null)
  assert.ok(m.review.some(n => n.title === 'Confirmed threat examples' && /Regenerate the report/.test(n.text)))
  assert.ok(!m.presenter.some(n => n.title === 'Operational true positives'))
})
test('alert titles say alerts in any letter case', () => {
  const p = pack(); alerts(p)
  put(p, 'OUT.4', [threat('Multi-stage INCIDENT involving Execution', 'High', 'Execution', '2026-09-01'), threat('Incidents correlated by Fusion', 'Medium', 'Execution', '2026-09-01'), threat('Suspicious incident from a rare location', 'Low', 'InitialAccess', '2026-09-01')])
  const m = build(p)
  assert.deepEqual(m.threats.examples.map(t => t.title), ['Multi-stage ALERT involving Execution', 'Alerts correlated by Fusion', 'Suspicious alert from a rare location'])
  put(p, 'OUT.4', [threat('Suspicious incident from a rare location', 'Low', 'InitialAccess', '2026-09-01'), threat('Title withheld', 'High', 'Execution', '2026-09-01')])
  assert.match(build(p).presenter.find(n => n.title === 'Confirmed threat titles withheld').text, /^1 confirmed alert is left out of the examples because its title may identify an account, address, host or other internal detail, could not be screened, or carries no title or date\./)
})
test('attack stages read in kill-chain order joined by commas, and severities rank in any letter case', () => {
  const p = pack(); alerts(p)
  put(p, 'OUT.4', [
    threat('Data staged for transfer', 'high', 'Exfiltration,commandandcontrol,CommandAndControl', '2026-06-02'),
    threat('Process control tampering', 'Medium', 'Impact,ImpairProcessControl,InhibitResponseFunction,PreAttack', '2026-09-03'),
    threat('Unfamiliar technique', 'LOW', 'SomeNewTactic', '2026-09-04'),
    threat('Unrated detection', '', 'Discovery,Execution,InitialAccess', '2026-09-05')
  ])
  const m = build(p)
  assert.deepEqual(m.threats.examples.map(t => [t.title, t.severity, t.stage]), [
    ['Data staged for transfer', 'High', 'Command and control, Exfiltration'],
    ['Process control tampering', 'Medium', 'Pre-attack, Inhibit response function, plus 2 more stages'],
    ['Unfamiliar technique', 'Low', 'Some new tactic'],
    ['Unrated detection', 'Not recorded', 'Initial access, Execution, plus 1 more stage']
  ])
  assert.deepEqual([m.threats.more, m.threats.moreAlerts], [0, 0])
  assert.match(m.presenter.find(n => n.title === 'Confirmed threat examples').text, /The table shows 4 confirmed alerts in 4 groups\.$/)
})
test('ties break on title, and moreAlerts counts the alerts in the hidden groups', () => {
  const p = pack(); alerts(p)
  put(p, 'OUT.4', 'FEDCBA'.split('').flatMap(c => [threat(`Threat ${c}`, 'High', 'Execution', '2026-09-01'), threat(`Threat ${c}`, 'High', 'Execution', '2026-09-01')]))
  const m = build(p)
  assert.deepEqual(m.threats.examples.map(t => t.title), ['Threat A', 'Threat B', 'Threat C', 'Threat D', 'Threat E'])
  assert.deepEqual([m.threats.more, m.threats.moreAlerts], [1, 2])
  assert.match(m.presenter.find(n => n.title === 'Confirmed threat examples').text, /The table shows 10 confirmed alerts in 5 groups\. 2 more sit in 1 further group\.$/)
})
test('a null OUT.4 row is skipped without a crash or an operational note', () => {
  const p = pack(); alerts(p)
  put(p, 'OUT.4', [null, threat('Password spray attack', 'Medium', 'CredentialAccess', '2026-08-22')])
  const m = build(p)
  assert.deepEqual(m.threats.examples.map(t => t.title), ['Password spray attack'])
  assert.equal(m.alerts.flagged, 0)
  assert.ok(!m.presenter.some(n => ['Operational true positives', 'Confirmed threat titles withheld'].includes(n.title)))
})
test('without the alert count there are no threat examples and no threat notes', () => {
  const p = pack(); alerts(p)
  p.manifest = p.manifest.filter(r => r.ResultId !== 'OUT.1'); delete p.results['OUT.1']
  put(p, 'OUT.4', [threat('Password spray attack', 'Medium', 'CredentialAccess', '2026-08-22'), threat('Title withheld', 'High', 'Collection', '2026-08-01'), threat('', 'Low', '', '2026-09-15')])
  const m = build(p)
  assert.equal(m.alerts, null)
  assert.equal(m.threats, null)
  const titles = ['Confirmed threat examples', 'Confirmed threat titles withheld', 'Operational true positives']
  assert.ok(![...m.presenter, ...m.review].some(n => titles.includes(n.title)))
})
test('every client-facing string keeps to the copy rules: no semicolons, arrows or emoji, and no angle brackets', () => {
  const p = pack(); alerts(p)
  put(p, 'EW.1', [{ Scope: 'Azure VM', OSPlatform: 'WindowsServer2022', Devices: 90, Onboarded: 87, CanBeOnboarded: 3, SensorActive: 87 }])
  put(p, 'EW.1-GAPS', [{ Reason: 'Covered by a third-party endpoint detection product', Product: 'CrowdStrike Falcon', Devices: 2, Eligible: true, Covered: true, Onboarded: 0, CanBeOnboarded: 2, NotSeen: 0, Other: 0 }, { Reason: 'Network virtual appliance, cannot run a sensor', Product: '', Devices: 1, Eligible: false, Covered: false, Onboarded: 0, CanBeOnboarded: 1, NotSeen: 0, Other: 0 }])
  put(p, 'IA.1', [{ UserType: 'Member', UsersSignedIn: 200, UsersChallenged: 150 }])
  p.results['IA.8-CA'] = [{ Flow: 'MFA at sign-in', Control: 'IA.1', PolicyRead: true, PolicySource: 'Raw', PolicyState: 'Scoped', EnforcedPolicies: 0, ExcludedIdentities: 0, DetailRead: false }]
  put(p, 'EW.10', [{ Machines: 40, WithinCadence: 36, OverduePatches: 12, AssessedWithin7d: 40 }])
  put(p, 'EW.10-EXCLUDED', [{ Machines: 5 }])
  put(p, 'NB.8', [{ Scope: 'Azure VM', Devices: 87, Compliant: 60 }])
  put(p, 'DP.2', [{ Vaults: 6, SoftDelete: 6, PurgeProtection: 0, RbacAuth: 3 }])
  const m = build(p)
  const text = JSON.stringify([m.headline, m.tiers, m.pillars, m.controls.map(c => [c.label, c.note, c.value]), m.priorities, m.whatNext, m.response, m.trend, m.threats, m.review, m.presenter, m.hardening])
  assert.ok(!/;/.test(text), text.match(/.{0,60};.{0,60}/)?.[0])
  assert.ok(!/[←-⇿➔➡]|->|=>/.test(text), 'arrows')
  assert.ok(!/[\u{1F300}-\u{1FAFF}☀-➿]/u.test(text), 'emoji')
  assert.ok(!/[<>]/.test(text), text.match(/.{0,60}[<>].{0,60}/)?.[0])
})
test('tenant score movement compares each snapshot against its own maximum', () => {
  const p = pack()
  put(p, 'POS.6', [{ ReadDate: '2026-10-10', Current: 450, Max: 1000, Percent: 45 }])
  put(p, 'POS.6-TREND', [{ Date: '2026-07-15', Current: 400, Max: 800, Percent: 50 }, { Date: '2026-10-10', Current: 450, Max: 1000, Percent: 45 }])
  assert.equal(build(p).tenantScore.delta, null, 'a wider maximum that lowers the percentage prints no gain')
  p.results['POS.6-TREND'][0] = { Date: '2026-07-15', Current: 320, Max: 800, Percent: 40 }
  assert.deepEqual(build(p).tenantScore.delta, { points: 5, since: 'Jul 2026', from: 40 })
  // The context file takes PreviousMax. Without it, the POS.6-TREND snapshot dated PreviousReadDate supplies the
  // maximum, and without that the movement line is omitted rather than taken against the current maximum.
  p.context = { TenantScore: { Current: 450, Max: 1000, ReadDate: '2026-10-01', Source: 'Portal reading', Previous: 400, PreviousMax: 800, PreviousReadDate: '2026-07-10' } }
  assert.equal(build(p).tenantScore.delta, null)
  delete p.context.TenantScore.PreviousMax
  const omitted = build(p)
  assert.equal(omitted.tenantScore.delta, null, 'no snapshot is dated Jul 10, so nothing stands in for the maximum')
  assert.ok(omitted.review.some(n => n.title === 'Microsoft tenant Secure Score movement'))
  p.context.TenantScore.PreviousReadDate = '2026-07-15'
  assert.equal(build(p).tenantScore.delta, null, 'the Jul 15 snapshot carries a maximum of 800, so 400 is 50% and no gain prints')
  p.context.TenantScore.Previous = 320
  assert.deepEqual(build(p).tenantScore.delta, { points: 5, since: 'Jul 2026', from: 40 })
})
test('the three threat measures stay apart, and only a reviewed context record prints an impact determination', () => {
  const gate = 'Based on the tactics Sentinel recorded on the alerts, none of the confirmed threats carried an exfiltration or impact tactic. Additional investigation evidence is required to confirm whether any data exposure or business impact occurred.'
  const p = pack(); alerts(p)
  p.results['OUT.2'][1].Incidents = 4 // below the minimum sample, so no timing and the executive tile falls back to the confirmed threats
  put(p, 'OUT.4', [threat('Log4j vulnerability exploit aka Log4Shell IP IOC', 'High', 'CommandAndControl', '2026-08-18'), threat('Password spray attack', 'Medium', 'CredentialAccess', '2026-08-22')])
  let m = build(p)
  assert.deepEqual([m.threatMeasures.malicious.value, m.threatMeasures.malicious.label, m.threatMeasures.incidents, m.threatMeasures.impact, m.impact], [3, 'Confirmed threats', null, null, null])
  assert.equal(m.impactStatement, gate)
  assert.equal(m.alerts.tacticPhrase, 'an exfiltration or impact tactic')
  assert.deepEqual(m.tiers.outcomes.filter(r => r.id !== 'OUT.1').map(r => [r.label, r.value]), [['True positives whose alerts carried an exfiltration or impact tactic', '0 of 3']])
  assert.deepEqual([m.headline.find(t => t.label === 'Confirmed threats').sub, m.headline.find(t => t.label === 'Confirmed threats').source], ['None carried an exfiltration or impact tactic', 'OUT.1. Read Oct 8, 2026.'])
  assert.ok(m.review.some(n => n.title === 'Impact determination' && /no reviewed Impact record/.test(n.text)))
  assert.match(m.presenter.find(n => n.title === 'Indicator-based true positives').text, /^A true-positive classification on an indicator detection, such as a Log4Shell IP or domain indicator match, confirms that the indicator was observed, not that exploitation or compromise occurred\. .* 1 of the 2 confirmed alerts with an attack stage carries an indicator in the title\./)
  assert.ok(!/\breached\b|no impact|did not reach/i.test(visible(m) + m.impactStatement), 'an outcome verb or an unrecorded impact determination reached the model')
  assert.ok(!/investigated/i.test(JSON.stringify([m.headline, m.tiers, m.threats, m.impactStatement])), 'a true positive never reads as investigated')
  // The flag count reads the same way when a tactic is recorded.
  put(p, 'OUT.4', [threat('Data staged for transfer', 'High', 'Exfiltration', '2026-08-18'), threat('Password spray attack', 'Medium', 'CredentialAccess', '2026-08-22')])
  assert.equal(build(p).impactStatement, 'Based on the tactics Sentinel recorded on the alerts, 1 of the 3 confirmed threats carried an exfiltration or impact tactic. Additional investigation evidence is required to confirm whether any data exposure or business impact occurred.')
  // A reviewed record bound to this pack's alert period: the determination prints with its reference and date,
  // and the tier gains a row.
  const win = { WindowStart: '2025-11-01', WindowEnd: '2026-09-30' }
  p.context = { Impact: { Confirmed: 0, Reviewed: '2026-10-10', Reference: 'CHG-123', ...win } }
  m = build(p)
  assert.deepEqual(m.impact, { confirmed: 0, reviewed: 'Oct 10, 2026', reference: 'CHG-123', source: 'Reviewed impact determination CHG-123, Oct 10, 2026, covering Nov 1, 2025 to Sep 30, 2026, from the reviewed context file.' })
  assert.equal(m.impactStatement, 'The reviewed investigation records confirm no data exposure or business impact from the 3 confirmed threats (CHG-123, reviewed Oct 10, 2026).')
  assert.deepEqual(m.threatMeasures.impact, { value: 0, label: 'Confirmed business impact', detail: 'Reviewed Oct 10, 2026, CHG-123', source: m.impact.source })
  assert.deepEqual(m.tiers.outcomes.find(r => r.id === 'CONTEXT'), { label: 'Confirmed data exposure or business impact', value: '0', id: 'CONTEXT' })
  assert.equal(m.headline.find(t => t.label === 'Confirmed threats').sub, 'No data exposure or business impact confirmed, reviewed Oct 10, 2026')
  assert.equal(m.headline.find(t => t.label === 'Confirmed threats').source, `OUT.1. Read Oct 8, 2026. ${m.impact.source}`, 'the tile cites the reviewed record beside OUT.1 when the determination drives its sub-line')
  assert.ok(!m.review.some(n => /^Impact determination/.test(n.title)))
  p.context.Impact.Confirmed = 2
  m = build(p)
  assert.equal(m.impactStatement, 'The reviewed investigation records confirm data exposure or business impact from 2 of the 3 confirmed threats (CHG-123, reviewed Oct 10, 2026).')
  assert.equal(m.headline.find(t => t.label === 'Confirmed threats').sub, '2 with confirmed data exposure or business impact')
  // The reviewed determination stays within the three rows the deck band shows, even at the 90 percent closure
  // boundary where the resolved share also earns a row.
  p.results['OUT.1'] = [{ Raised: 100, Closed: 90, Open: 10, TruePositive: 3, ClosedUnclassified: 5 }]
  m = build(p)
  assert.deepEqual(m.tiers.outcomes.map(r => r.label), ['Alerts triaged', 'Confirmed threats', 'Confirmed data exposure or business impact', 'Alerts closed', 'True positives whose alerts carried an exfiltration or impact tactic'])
  p.results['OUT.1'] = [{ Raised: 100, Closed: 80, Open: 20, TruePositive: 3, ClosedUnclassified: 5 }]
  put(p, 'OUT.4', [threat('Log4j vulnerability exploit aka Log4Shell IP IOC', 'High', 'CommandAndControl', '2026-08-18'), threat('Password spray attack', 'Medium', 'CredentialAccess', '2026-08-22')])
  // A context file reused from an earlier period, or reviewed before the period ended, never carries a determination forward.
  p.context = { Impact: { Confirmed: 0, Reviewed: '2026-06-30', Reference: 'Q2-review', WindowStart: '2026-04-01', WindowEnd: '2026-06-30' } }
  m = build(p)
  assert.equal(m.impact, null)
  assert.equal(m.impactStatement, gate)
  assert.match(m.review.find(n => n.title === 'Impact determination needs review').text, /^The context Impact record was omitted because it covers Apr 1 to Jun 30, 2026 and this pack's alert period is Nov 1, 2025 to Sep 30, 2026\./)
  p.context = { Impact: { Confirmed: 0, Reviewed: '2026-09-15', Reference: 'CHG-123', ...win } }
  m = build(p)
  assert.equal(m.impact, null)
  assert.match(m.review.find(n => n.title === 'Impact determination needs review').text, /because its review is dated Sep 15, 2026, before the alert period ended on Sep 30, 2026/)
  assert.equal(build({ ...p, context: { Impact: { Confirmed: 0, Reviewed: '2026-09-30', Reference: 'CHG-123', ...win } } }).impact.reviewed, 'Sep 30, 2026', 'a review dated on the last day of the period counts')
  // Malformed or inconsistent records are omitted with a review note, and the gate statement returns.
  put(p, 'OUT.4', [threat('Log4j vulnerability exploit aka Log4Shell IP IOC', 'High', 'CommandAndControl', '2026-08-18'), threat('Password spray attack', 'Medium', 'CredentialAccess', '2026-08-22')])
  for (const bad of [{ Confirmed: 0 }, { Confirmed: 0, Reviewed: '2026-10-10', Reference: 'CHG-123' }, { Confirmed: -1, Reviewed: '2026-10-10', Reference: 'CHG-123', ...win }, { Confirmed: 0, Reviewed: '2026-02-31', Reference: 'CHG-123', ...win }, { Confirmed: 4, Reviewed: '2026-10-10', Reference: 'CHG-123', ...win }, { Confirmed: 0, Reviewed: '2026-10-10', Reference: 'CHG-123', WindowStart: '2025-11-01', WindowEnd: '2026-09-31' }, 'none']) {
    p.context = { Impact: bad }
    m = build(p)
    assert.equal(m.impact, null, JSON.stringify(bad))
    assert.equal(m.impactStatement, gate, JSON.stringify(bad))
    assert.equal(m.review.some(n => n.title === 'Impact determination needs review'), typeof bad === 'object', JSON.stringify(bad))
  }
  // A pack whose rows carry no tactics keeps the wider flag scope in the phrase and the statement.
  put(p, 'OUT.4', [{ Severity: 'High', ExfilOrImpactTactic: true }, { Severity: 'Low', ExfilOrImpactTactic: false }])
  p.context = null
  m = build(p)
  assert.equal(m.alerts.tacticPhrase, 'a collection, exfiltration or impact tactic')
  assert.equal(m.impactStatement, 'Based on the tactics Sentinel recorded on the alerts, 1 of the 3 confirmed threats carried a collection, exfiltration or impact tactic. Additional investigation evidence is required to confirm whether any data exposure or business impact occurred.')
})
test('confirmed threat severities are counted per alert before grouping, so a mixed group never reads as all high', () => {
  const p = pack(); alerts(p)
  put(p, 'OUT.4', [{ Threat: 'Suspicious sign-in detected', Severity: 'High', Tactics: 'InitialAccess', Created: '2026-08-01', ExfilOrImpactTactic: false }, ...Array.from({ length: 9 }, (_, i) => ({ Threat: 'Suspicious sign-in detected', Severity: 'Low', Tactics: 'InitialAccess', Created: `2026-08-0${i + 1}`, ExfilOrImpactTactic: false }))])
  const m = build(p)
  assert.deepEqual([m.threats.examples[0].severity, m.threats.examples[0].alerts], ['High', 10])
  assert.deepEqual(m.threats.severities, { High: 1, Medium: 0, Low: 9, Informational: 0 })
  assert.equal(m.threats.alerts, 10)
})
test('the nine in ten line describes closure only, with automated and unclassified closures in the cohort', () => {
  const p = pack(); alerts(p, { auto: 20 })
  p.results['OUT.2'][1].AutoClosed = 4
  p.results['OUT.1'][0].ClosedUnclassified = 5
  const m = build(p)
  assert.equal(m.response.p90.note, 'Nine in ten alerts triaged and closed within this time. Based on 30 closed alerts.')
  assert.equal(m.headline.find(t => /Median time to close/.test(t.label)).sub, 'Nine in ten triaged and closed within 45 min')
  assert.ok(!/investigated|resolved/.test(JSON.stringify([m.response, m.headline.find(t => /Median time/.test(t.label))])), 'closure time never reads as investigation or resolution')
  assert.ok(m.tiers.outcomes.every(r => !/resulted in/.test(r.label)))
})
test('a score movement that rounds to zero is no gain, so no surface prints up 0 points', () => {
  const p = pack(); alerts(p)
  put(p, 'POS.1', [{ Current: 50, Max: 100, Percent: 50, Subscriptions: 1 }])
  put(p, 'POS.7', [{ Month: '2026-07-01', Current: 50, Max: 100, Percent: 50 }, { Month: '2026-10-01', Current: 50, Max: 100, Percent: 50 }])
  p.context = { TenantScore: { Current: 450.2, Max: 1000, ReadDate: '2026-10-01', Source: 'Portal reading', Previous: 450, PreviousMax: 1000, PreviousReadDate: '2026-07-10' } }
  const m = build(p)
  assert.equal(m.cloudScore.delta, null, 'a flat cloud score prints no gain')
  assert.deepEqual(m.cloudScore.trend.map(r => r.pct), [50, 50], 'the trend still carries both readings')
  assert.equal(m.tenantScore.delta, null, 'a tenant movement under 0.05 points prints no gain')
  const tile = m.headline.find(t => /tenant Secure Score/.test(t.label))
  assert.deepEqual([tile.sub, tile.tone], ['Read Oct 1, 2026', ''])
  assert.ok(!/Up 0 points/.test(JSON.stringify([m.headline, m.tiers])), 'no surface reads up 0 points')
  p.context.TenantScore.Current = 451
  assert.deepEqual(build(p).tenantScore.delta, { points: 0.1, since: 'Jul 2026', from: 45 })
})
test('an Actions record carries a reviewed status only when it names a known key, a known status and the period it covers', () => {
  const record = (extra = {}) => ({ Key: 'critical', Status: 'Scheduled', Owner: 'Client infrastructure team', TargetDate: '2026-11-30', Reference: 'CHG-400', Reviewed: '2026-10-10', WindowStart: '2025-11-01', WindowEnd: '2026-09-30', ...extra })
  const withActions = (actions, delivered = []) => { const p = pack(); p.context = { Actions: actions, Delivered: delivered }; return build(p) }
  const m = withActions([record()])
  assert.deepEqual(m.actions, [{ key: 'critical', status: 'Scheduled', label: 'Scheduled', owner: 'Client infrastructure team', targetDate: 'Nov 30, 2026', verification: '', reference: 'CHG-400', reviewed: 'Oct 10, 2026', source: 'Reviewed action status CHG-400, Oct 10, 2026, from the reviewed context file.' }])
  assert.ok(!m.review.some(r => r.title === 'Action status needs review'))
  const omitted = (actions, reason, delivered) => {
    const built = withActions(actions, delivered)
    assert.deepEqual(built.actions, [], reason.source)
    assert.ok(built.review.some(r => r.title === 'Action status needs review' && reason.test(r.text)), reason.source)
  }
  omitted([record({ Key: 'everything' })], /its Key is not one of drift, critical/)
  omitted([record({ Status: 'Done' })], /its Status is not one of Proposed, PendingValidation, AwaitingApproval, Approved, Scheduled, InProgress, Verified/)
  omitted([record({ Reference: '' })], /lacks a Reference, a Reviewed date/)
  omitted([record({ WindowStart: '2026-07-01' })], /covers Jul 1 to Sep 30, 2026 and this pack's alert period is Nov 1, 2025 to Sep 30, 2026/)
  omitted([record({ Reviewed: '2026-10-01' })], /dated Oct 1, 2026, before the evidence was collected on Oct 8, 2026/)
  omitted([record({ TargetDate: '2026-13-01' })], /TargetDate is not a date/)
  omitted([record({ TargetDate: null })], /a Scheduled item needs a TargetDate/)
  omitted([record({ Status: 'Verified' })], /a Verified item needs a Delivered record in this alert period with the same Reference/)
  omitted([record({ Status: 'Verified' })], /same Reference/, [{ Title: 'Patch run', Outcome: 'Patched.', Reference: 'CHG-999', CompletedDate: '2026-09-01' }])
  // A second record for the same key is omitted, and the first stands.
  const twice = withActions([record(), record({ Status: 'Approved' })])
  assert.deepEqual(twice.actions.map(x => x.status), ['Scheduled'])
  assert.ok(twice.review.some(r => /record for critical was omitted because another record already carries the same Key/.test(r.text)))
  // Verified stands only beside a Delivered record with the same reference, and a status needs no owner or target.
  const verified = withActions([record({ Status: 'Verified', Owner: '', TargetDate: '', Verification: 'BKL.1 reads no critical finding.' })], [{ Title: 'Patch run', Outcome: 'Patched.', Reference: 'CHG-400', CompletedDate: '2026-09-01' }])
  assert.deepEqual(verified.actions.map(x => [x.label, x.owner, x.targetDate, x.verification]), [['Verified', '', '', 'BKL.1 reads no critical finding.']])
  assert.deepEqual(withActions([record({ Status: 'InProgress', TargetDate: undefined })]).actions.map(x => x.label), ['In progress'])
  assert.deepEqual(build(pack()).actions, [], 'no record, no status')
})
test('the roadmap page words planned work as a recommendation and never promises the MFA method update as a non-event', () => {
  const p = pack(); alerts(p)
  put(p, 'IA.2', [{ Bucket: 'Retiring: SMS or voice', DistinctUsers: 7 }])
  put(p, 'BKL.1', [{ Scope: 'Azure VM', Software: 'Application', VulnerabilitySeverityLevel: 'Critical', ExploitableCves: 6, Devices: 3 }])
  const nodes = {}
  const document = { body: { dataset: {} }, querySelectorAll: () => [], getElementById: id => nodes[id] || (nodes[id] = { textContent: id === 'report-data' ? JSON.stringify(p) : '', addEventListener() {} }) }
  vm.runInNewContext(fs.readFileSync(path.join(__dirname, '../report/report-render.js'), 'utf8'), { EbrReport: require('../report/report-model.js'), document, window: {} })
  const html = nodes.report.innerHTML
  assert.ok(html.includes('Atmosera recommends staging each enforcement in an audit or report-only mode where the control supports one, reviewing it with your team, then turning it on.'))
  assert.ok(html.includes('<h3>How this order is proposed</h3><p>Every item on this board comes from a reading in the collected evidence. The order is a recommendation for agreement at this review'))
  assert.ok(html.includes('<h3>7 of your users signed in with text message or voice over the last 30 days. Atmosera recommends moving each one to a passkey well ahead of February 1, 2027 (July 1, 2027 for Global Administrators and external users).</h3>'))
  assert.ok(html.includes('From September 1, 2026, Microsoft enables passkeys for users enabled for text message or voice') && html.includes('this blocking prompt has no opt-out. Whether these users hold another registered MFA method is not yet evaluated.'))
  assert.ok(html.includes('<strong>Register a passkey</strong>A passkey in Microsoft Authenticator, Windows Hello for Business or a FIDO2 key, in guided waves. Authenticator push stays supported.'))
  assert.ok(html.includes('A telephony provider stays only for a documented regulatory or operational need.'))
  assert.ok(!/already sign in with Microsoft Authenticator|need to update their MFA method|Register a stronger method/.test(html))
  assert.ok(html.includes('<p class="success"><strong>Outcome</strong> Every affected user registered on a replacement method before February 1, 2027 (July 1, 2027 for Global Administrators and external users), the fallback tested, and no rise in failed sign-ins after enforcement.</p>'))
  assert.ok(!/waits on discovery|scoped and sequenced|already scoped|Every enforcement is staged|non-event|No blocked sign-ins|no sign-in is blocked|\bscheduled\b/i.test(html), html.match(/.{0,60}(waits on discovery|scoped and sequenced|already scoped|Every enforcement is staged|non-event|blocked sign-ins|scheduled).{0,60}/i)?.[0])
})
