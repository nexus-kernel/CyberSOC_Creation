// The story behind the deck (report/report-story.js): the rules from the Oct 12, 2026 deck review.
// Roadmap completeness, the response timing floor, open alerts kept out, drift first in Now, access
// asks only for permission gaps, grammar and the copy rules.
const { test } = require('node:test')
const assert = require('node:assert/strict')
const { build, MEDIAN_FLOOR } = require('../report/report-model.js')
const { buildStory, CATALOG } = require('../report/report-story.js')

function quarterPack() {
  const p = {
    parameters: { ClientName: 'Example', WindowStart: '2026-07-01', WindowEnd: '2026-09-30', RecentStart: '2026-07-01', PostureReadDate: '2026-10-12', DefenderApi: 'available', Subscriptions: ['s1'], Workspaces: [{ Name: 'w1', CustomerId: 'w1' }], AlertScope: 'Ticketed incidents only', PatchCadenceDays: 30 },
    manifest: [], results: {}, context: null
  }
  const put = (id, rows, status = 'OK', extra = {}) => { p.manifest = p.manifest.filter(r => r.ResultId !== id); p.manifest.push({ ResultId: id, Status: status, Rows: rows.length, ReadTimeUtc: '2026-10-12T10:00:00Z', ...extra }); p.results[id] = rows }
  put('P0.1-XDRDUP', [{ XdrIncidents: 20, InMultipleWorkspaces: 0 }])
  put('OUT.1', [{ Raised: 615, Closed: 238, Open: 377, TruePositive: 2, BenignPositive: 187, FalsePositive: 39, ClosedUnclassified: 10 }])
  const timing = [{ Scope: 'High', Incidents: 208, AutoClosed: 0, MedianCloseMin: 7, P90CloseMin: 36 }, { Scope: 'Medium', Incidents: 15, AutoClosed: 0, MedianCloseMin: 178, P90CloseMin: 1302 }, { Scope: 'Low', Incidents: 15, AutoClosed: 0, MedianCloseMin: 99, P90CloseMin: 1608 }, { Scope: 'All', Incidents: 238, AutoClosed: 0, MedianCloseMin: 8, P90CloseMin: 76 }]
  put('OUT.2', timing); put('OUT.2-ANALYST', timing)
  put('OUT.3', [{ Month: '2026-07-01', Total: 105, High: 6, Medium: 14, Low: 85, Informational: 0 }, { Month: '2026-08-01', Total: 163, High: 22, Medium: 20, Low: 121, Informational: 0 }, { Month: '2026-09-01', Total: 347, High: 208, Medium: 7, Low: 132, Informational: 0 }])
  put('OUT.4', [{ IncidentNumber: 1, Severity: 'High', Tactics: 'InitialAccess', ExfilOrImpactTactic: false }, { IncidentNumber: 2, Severity: 'High', Tactics: 'Execution', ExfilOrImpactTactic: false }])
  put('OUT.5', [{ ProductName: 'Azure Sentinel', AlertSeverity: 'High', Alerts: 659 }])
  put('P0.1-BY-WORKSPACE', [{ WorkspaceId: 'w1', SourceTable: 'SecurityIncident', EarliestRecord: '2026-01-01', Records: 900 }])
  put('IA.1', [{ UserType: 'Member', UsersSignedIn: 194, UsersChallenged: 180 }])
  put('IA.2', [{ Bucket: 'Authenticator or OTP', DistinctUsers: 185 }, { Bucket: 'Retiring: SMS or voice', DistinctUsers: 40 }, { Bucket: 'Phishing-resistant', DistinctUsers: 3 }])
  put('IA.11', [{ SignInRiskPolicies: 1, SignInRiskAllUsers: true, UserRiskPolicies: 0, UserRiskAllUsers: false, InForce: false }])
  put('EW.10', [{ Machines: 70, WithinCadence: 70, OverduePatches: 0, AssessedWithin7d: 70 }])
  put('DP.1', [{ Accounts: 42, SecureTransfer: 41, MinTls12: 32, AnonymousBlobOff: 34, PublicNetworkOff: 0 }])
  put('DP.2', [{ Vaults: 4, SoftDelete: 4, PurgeProtection: 2, RbacAuth: 2 }])
  put('DP.7', [{ ActionType: 'ZAP', Events: 748, Succeeded: 748 }])
  put('NB.1', [{ WorkloadSubnets: 36, Segmented: 14 }])
  put('BKL.1', [{ Scope: 'Azure VM', Software: 'Application', VulnerabilitySeverityLevel: 'Critical', ExploitableCves: 7, Devices: 3 }])
  put('POS.1', [{ Current: 25.67, Max: 43, Subscriptions: 1, Percent: 59.7 }])
  put('POS.7', [{ Month: '2026-07-01', Current: 23.04, Max: 43, Percent: 53.6 }, { Month: '2026-10-01', Current: 25.67, Max: 43, Percent: 59.7 }])
  put('DP.8', [], 'UNAVAILABLE', { AccessGap: true }) // the token was not permitted to read sharing settings
  put('EW.13', [], 'UNAVAILABLE', { AccessGap: false }) // a service error, not a permission gap
  return p
}
const story = p => { const m = build(p); return { m, s: buildStory(m, p) } }

test('every control below E lands on the roadmap, and every foundational one is drift in Now', () => {
  const m = build(quarterPack())
  // Push every control below E to prove the catalog covers all of them.
  for (const c of m.controls) Object.assign(c, { mark: 'N', pct: 10, good: 1, total: 10, measured: true, na: false, value: '1 of 10', boolean: false })
  const s = buildStory(m, quarterPack())
  assert.deepEqual(s.unmapped, [], `controls with no roadmap item: ${s.unmapped.join(', ')}`)
  const onRoadmap = new Set(s.roadmap.flatMap(h => h.items.flatMap(i => (i.controls || []).map(c => c.label))))
  for (const c of m.controls) assert.ok(onRoadmap.has(c.label), c.label)
  const now = s.roadmap.find(h => h.key === 'now')
  assert.equal(now.items[0].key, 'drift')
  assert.equal(now.items[0].controls.length, m.controls.filter(c => c.tier === 'foundational').length)
  assert.ok(CATALOG.every(e => e.horizon === 'next' || e.horizon === 'later'))
})
test('response speed keeps the fixed high severity cohort and shows a median under the floor with its note', () => {
  const { m, s } = story(quarterPack())
  assert.deepEqual([m.timing.find(r => r.scope === 'High').median.value, m.timing.find(r => r.scope === 'All').median.value], ['7 min', '8 min'], 'every median is shown')
  assert.equal(m.timing.find(r => r.scope === 'Medium').median.value, '3 hr')
  assert.deepEqual([s.speed.value, s.speed.label], ['7 min', 'median time to close, high severity alerts'])
  assert.equal(s.speed.sub, '208 alerts closed. Nine in ten triaged and closed within 36 min. Median under 20 minutes, covered in the review.')
  assert.equal(s.kpis[2].sub, 'Nine in ten triaged and closed within 36 min. Median under 20 minutes, covered in the review')
  assert.equal(s.takeaways.operations, '615 alerts triaged this quarter. High-severity alerts closed in a median of 7 min. Median under 20 minutes, covered in the review.')
  assert.ok(MEDIAN_FLOOR === 20)
  // A 90th percentile over one hour stays on the KPI with its note, never swapped for another measure.
  const p = quarterPack(); p.results['OUT.2'][0].MedianCloseMin = 30; p.results['OUT.2'][0].P90CloseMin = 300
  const slow = story(p).s
  assert.deepEqual([slow.speed.value, slow.kpis[2].sub], ['30 min', 'Nine in ten triaged and closed within 5 hr. 90th percentile over one hour, covered in the review'])
})
test('open alerts and the severity spike stay out of the story', () => {
  const { s } = story(quarterPack())
  const text = JSON.stringify([s.kpis, s.wins, s.watch, s.asks, s.summaryWins, s.takeaways, s.roadmap])
  assert.ok(!/\b377\b|\bopen alert|\b208\b.*\bup from\b|confirm owners|owners for referred/i.test(text))
  assert.ok(!s.asks.some(a => /alert/i.test(a.title)))
})
test('the story carries the wins, asks and takeaways the review asked for, worded within the copy rules', () => {
  const { s } = story(quarterPack())
  assert.equal(s.quarter, 'Q3 2026')
  assert.deepEqual(s.kpis.map(k => k.value), ['615', '0 of 2', '7 min', '59.7%'])
  assert.deepEqual(s.kpis.map(k => k.label), ['Alerts triaged', 'True positives whose alerts carried an exfiltration or impact tactic', 'Median time to close, high severity alerts', 'Defender for Cloud secure score'])
  assert.equal(s.kpis[1].sub, 'Both classified as true positives by the SOC', 'a true positive is a classification, never an investigation or a closure')
  assert.equal(s.kpis[0].sub, 'Jul 1 to Sep 30, 2026', 'the alert KPI carries the period, not the detection count')
  assert.equal(s.kpis[3].sub, 'Up 6.1 points since Jul 2026, from 53.6%')
  assert.deepEqual(s.wins.map(w => w.eyebrow), ['Confirmed threats', 'Response speed', 'Posture', 'Identity', 'Patching', 'Email protection'])
  assert.deepEqual([s.wins[0].value, s.wins[0].label, s.wins[0].sub], ['0 of 2', 'confirmed threats carried an exfiltration or impact tactic', 'Both classified as true positives by the SOC this quarter.'])
  assert.equal(new Set(s.wins.map(w => w.area)).size, s.wins.length, 'at most one win per area')
  assert.equal(s.takeaways.summary, 'Neither confirmed threat carried an exfiltration or impact tactic, and secure score rose 6.1 points.')
  assert.match(s.takeaways.posture, /foundational controls are enforced( \(\d+ on a small sample\))?\. (Two|Three|Four) read below the baseline and are first on the roadmap\./)
  assert.ok(!/\breached\b|no impact|did not reach|investigated/i.test(JSON.stringify(s)), 'an outcome verb or an unrecorded impact determination reached the story')
  const spoken = JSON.stringify([s.takeaways, s.roadmap.map(h => h.items.map(i => [i.title, i.evidence])), s.watch, s.wins, s.asks, s.summaryWins, s.matrix])
  assert.ok(!/\bdrift|at build|regress/i.test(spoken), 'the story never claims a regression or a build-time configuration')
  assert.ok(s.takeaways.pillars && s.takeaways.priorities, 'the grounding slides have takeaways')
  assert.deepEqual(s.drift.map(c => c.short).sort(), ['Key Vault purge protection', 'anonymous blob access', 'storage TLS 1.2'].sort())
  assert.deepEqual(s.asks.map(a => a.title), ['Move users off text message and voice MFA', 'Grant read access for one ungraded control', 'Approve the user-risk policy', 'Agree a segmentation design and change windows'])
  assert.equal(s.asks[1].body, 'Sharing settings.', 'only the permission gap is an access ask, not the service error')
  // The executive summary names the items that need action from the client. Read access is Atmosera's to arrange.
  assert.deepEqual(s.summaryAsks, [{ value: '40 users', label: 'on text message or voice MFA ahead of Feb 1, 2027 (Jul 1, 2027 for Global Administrators and external users)' }, { value: '1 control', label: 'Approve the user-risk policy' }, { value: '2 controls', label: 'Agree a segmentation design and change windows' }])
  assert.ok(!/passwordless/i.test(JSON.stringify(s)), 'the story never frames the MFA method update as passwordless')
  assert.ok(!/need to update their MFA method|still rel(y|ies)/.test(JSON.stringify(s)), 'use alone is never read as sole reliance')
  assert.equal(s.roadmap.flatMap(h => h.items).find(i => i.key === 'methods').evidence, '40 users on text message or voice, ahead of Feb 1, 2027 (Jul 1, 2027 for Global Administrators and external users)')
  assert.equal(s.deadlineDays, 112)
  const all = JSON.stringify(s)
  assert.ok(!/;|→|←|\bcontain(ed|ment)\b|\(null\)|\bincidents?\b/i.test(all.replace(/\\u[0-9a-f]{4}/gi, '')), all.match(/.{0,40}(;|contain|\(null\)|incident).{0,40}/i)?.[0])
})
test('a tiny population never stands as a win or leads a pillar, and a policy-only pillar takes its measure from the pillar page', () => {
  const p = quarterPack()
  p.results['EW.10'] = [{ Machines: 2, WithinCadence: 2, OverduePatches: 0, AssessedWithin7d: 2 }]
  p.manifest.push({ ResultId: 'EW.1', Status: 'OK', Rows: 1, ReadTimeUtc: '2026-10-12T10:00:00Z' })
  p.results['EW.1'] = [{ Scope: 'Azure VM', OSPlatform: 'WindowsServer2022', Devices: 89, Onboarded: 88, CanBeOnboarded: 1, Unsupported: 0, InsufficientInfo: 0, SensorActive: 88 }]
  const { m, s } = story(p)
  assert.equal(m.controls.find(c => c.id === 'EW.10').value, '2 of 2', 'the control itself still reads 2 of 2')
  const endpoint = s.wins.find(w => w.area === 'endpoint')
  assert.equal(endpoint.value, '88 of 89', '2 of 2 is not a quarter win')
  assert.equal(endpoint.eyebrow, 'Endpoint')
  const row = s.matrix.find(r => r.group === 'Endpoint and workload')
  assert.ok(!/2 of 2/.test(row.measure) && /88 of 89/.test(row.measure), row.measure)
  // A pillar whose controls are all policy readings takes the sign-in ratio and the callout from the pillar page.
  const q = quarterPack()
  q.results['IA.8-CA'] = [{ Flow: 'MFA at sign-in', Control: 'IA.1', PolicyRead: true, PolicySource: 'Raw', PolicyState: 'Enforced', EnforcedPolicies: 1, ExcludedIdentities: 0, DetailRead: false }]
  const identity = story(q).s.matrix.find(r => r.group === 'Identity and access')
  assert.equal(identity.measure, '180 of 194 users challenged for MFA at sign-in · 3 users already on phishing-resistant sign-in')
  // The fallback never bypasses the minimum population, never repeats a control, and never fires for a pillar
  // that has ratio controls of its own (a two-account storage estate reads no headline measure).
  const r = quarterPack()
  r.results['DP.1'] = [{ Accounts: 2, SecureTransfer: 2, MinTls12: 2, AnonymousBlobOff: 2, PublicNetworkOff: 0 }]
  r.results['DP.2'] = [{ Vaults: 2, SoftDelete: 2, PurgeProtection: 2, RbacAuth: 2 }]
  delete r.results['DP.7']; r.manifest = r.manifest.filter(x => x.ResultId !== 'DP.7')
  const data = story(r).s.matrix.find(x => x.group === 'Data protection')
  assert.equal(data.measure, '', data.measure)
  q.results['IA.1'] = [{ UserType: 'Member', UsersSignedIn: 4, UsersChallenged: 4 }]
  q.results['IA.2'] = [{ Bucket: 'Retiring: SMS or voice', DistinctUsers: 40 }, { Bucket: 'Phishing-resistant', DistinctUsers: 3 }]
  assert.equal(story(q).s.matrix.find(x => x.group === 'Identity and access').measure, '3 users already on phishing-resistant sign-in', 'a tiny sign-in population drops out and the callout stands alone')
})
// Issue #24, as the owner decided on Oct 18, 2026: patch cadence 2 of 2 with 18 machines excluded by tag stays in the
// tier totals by its mark, the count names it beside the total, and the register flags it. Never a lead or a win.
test('a 2 of 2 control with exclusions is no lead and no win, is flagged in the register, and the tier counts name it', () => {
  const p = quarterPack()
  p.results['EW.10'] = [{ Machines: 2, WithinCadence: 2, OverduePatches: 0, AssessedWithin7d: 2 }]
  p.manifest.push({ ResultId: 'EW.10-EXCLUDED', Status: 'OK', Rows: 1, ReadTimeUtc: '2026-10-12T10:00:00Z' })
  p.results['EW.10-EXCLUDED'] = [{ Machines: 18 }]
  // Full samples elsewhere, so the only small sample is the patch cadence row.
  p.results['DP.1'] = [{ Accounts: 42, SecureTransfer: 42, MinTls12: 42, AnonymousBlobOff: 42, PublicNetworkOff: 42 }]
  p.results['DP.2'] = [{ Vaults: 40, SoftDelete: 40, PurgeProtection: 40, RbacAuth: 40 }]
  const { m, s } = story(p)
  const patch = m.controls.find(c => c.id === 'EW.10')
  assert.deepEqual([patch.value, patch.mark, patch.smallSample], ['2 of 2', 'E', true])
  assert.deepEqual(m.controls.filter(c => c.smallSample).map(c => c.id), ['EW.10'])
  // Not a win and not a pillar lead.
  assert.ok(!s.wins.some(w => w.source === patch.source || /patched/.test(w.label)), JSON.stringify(s.wins.map(w => w.label)))
  assert.ok(!/patched in cadence|2 of 2/.test(s.matrix.find(r => r.group === 'Endpoint and workload').measure))
  // Flagged in the register, with both populations on the detail line.
  const row = s.register.find(r => r.group === 'Endpoint and workload').foundational.find(c => c.id === 'EW.10')
  assert.deepEqual([row.chip, row.sampleText, row.detail], ['E', 'small sample', '2 assessed · 18 excluded by tag'])
  // Counted toward enforced and measured by its mark, and named beside every tier total.
  const found = m.controls.filter(c => c.tier === 'foundational' && c.mark)
  assert.deepEqual(s.foundational, { enforced: found.filter(c => c.mark === 'E').length, measured: found.length, small: 1 })
  const total = `${s.foundational.enforced} of ${s.foundational.measured}`
  assert.equal(s.takeaways.posture.split('.')[0], `${total} foundational controls are enforced (1 on a small sample)`)
  // The KPI strip is full (alerts, threats, speed, score), so the total leads the summary wins.
  assert.ok(!s.kpis.some(k => k.area === 'controls'))
  assert.deepEqual(s.summaryWins[0], { value: total, label: 'foundational controls enforced across five pillars (1 on a small sample)' })
  const endpoint = s.matrix.find(r => r.group === 'Endpoint and workload')
  assert.equal(endpoint.foundational.small, 1)
  assert.ok(s.matrix.filter(r => r !== endpoint).every(r => r.foundational.small === 0 && r.defense.small === 0))
  // With no score reading the total takes the fourth KPI, and its sub-line names the small sample.
  for (const id of ['POS.1', 'POS.7']) { delete p.results[id]; p.manifest = p.manifest.filter(r => r.ResultId !== id) }
  assert.deepEqual(story(p).s.kpis.find(k => k.area === 'controls'), { value: total, label: 'Foundational controls enforced', sub: 'Across five pillars, 1 on a small sample', area: 'controls' })
  // Without the small sample nothing is annotated.
  const plain = quarterPack()
  plain.results['DP.1'] = p.results['DP.1']; plain.results['DP.2'] = p.results['DP.2']
  const u = story(plain).s
  assert.equal(u.foundational.small, 0)
  assert.ok(!/small sample/.test(JSON.stringify(u)), JSON.stringify(u).match(/.{0,80}small sample.{0,40}/)?.[0])
})
test('Defender for Identity and domain controller telemetry gaps sit in Later with the licensing ask, never in the foundational gaps', () => {
  // Defense in depth since Oct 16, 2026: both need Defender for Identity licensing and a sensor on each domain controller.
  const p = quarterPack()
  p.manifest.push({ ResultId: 'DR.11', Status: 'UNAVAILABLE', Rows: 0, ReadTimeUtc: '2026-10-12T10:00:00Z', AccessGap: false, NotOnboarded: true })
  p.manifest.push({ ResultId: 'NB.10', Status: 'OK', Rows: 1, ReadTimeUtc: '2026-10-12T10:00:00Z' })
  p.results['NB.10'] = [{ Scope: 'Azure VM', Devices: 3, Compliant: 0 }] // domain controllers in Azure, so the control applies
  const { m, s } = story(p)
  assert.deepEqual([m.controls.find(c => c.id === 'DR.11').value, m.controls.find(c => c.id === 'DR.11').tier], ['Not in force', 'defense'])
  assert.ok(!s.drift.some(c => c.id === 'DR.11'), 'not a foundational gap')
  assert.equal(s.licensed, undefined, 'no foundational control waits on licensing')
  const later = s.roadmap.find(h => h.key === 'later').items.find(i => i.key === 'mdi')
  assert.ok(later && later.controls[0].id === 'DR.11', 'Defender for Identity sits in Later')
  assert.equal(later.ask.title, 'Approve Defender for Identity licensing')
  // As a defense in depth item its ask takes its turn in horizon order, after Now and Next and after segmentation,
  // which sits earlier in Later. With segmentation and storage network access enforced it makes the four.
  assert.deepEqual(s.asks.map(a => a.key), ['methods', 'access', 'idp', 'segment'])
  const q = JSON.parse(JSON.stringify(p)); q.results['NB.1'] = [{ WorkloadSubnets: 36, Segmented: 36 }]; q.results['DP.1'][0].PublicNetworkOff = 42
  assert.deepEqual(buildStory(build(q), q).asks.map(a => [a.key, a.title]).slice(-1), [['mdi', 'Approve Defender for Identity licensing']])
  assert.ok(!s.asks.some(a => /read access/.test(a.title) && /Defender for Identity/.test(a.body)), 'never a read access ask')
  assert.ok(!/licensing/.test(s.takeaways.posture), s.takeaways.posture)
  assert.equal(s.watch.find(w => /foundational controls? reads? below enforced/.test(w.label)).value, String(s.drift.length))
  // Domain controller telemetry reads Not in force with no events, and joins the same item and ask.
  p.manifest.push({ ResultId: 'DR.4', Status: 'EMPTY', Rows: 0, ReadTimeUtc: '2026-10-12T10:00:00Z' }); p.results['DR.4'] = []
  const both = story(p)
  assert.deepEqual([both.m.controls.find(c => c.id === 'DR.4').value, both.m.controls.find(c => c.id === 'DR.4').tier], ['Not in force', 'defense'])
  assert.ok(!both.s.drift.some(c => c.id === 'DR.4'))
  const mdi = both.s.roadmap.find(h => h.key === 'later').items.find(i => i.key === 'mdi')
  assert.deepEqual(mdi.controls.map(c => c.id).sort(), ['DR.11', 'DR.4'])
  q.manifest.push({ ResultId: 'DR.4', Status: 'EMPTY', Rows: 0, ReadTimeUtc: '2026-10-12T10:00:00Z' }); q.results['DR.4'] = []
  const asks = buildStory(build(q), q).asks.filter(a => a.key === 'mdi')
  assert.deepEqual(asks.map(a => a.lead), ['2 controls'], 'one licensing ask covers both')
  // Sensors licensed and healthy with no domain controller events is an ingestion fault: the telemetry gap stays in
  // the Later item, but never asks the client to license what it already holds.
  const t = JSON.parse(JSON.stringify(q))
  t.manifest = t.manifest.filter(r => r.ResultId !== 'DR.11'); t.manifest.push({ ResultId: 'DR.11', Status: 'OK', Rows: 1, ReadTimeUtc: '2026-10-12T10:00:00Z' })
  t.results['DR.11'] = [{ Sensors: 4, Healthy: 4 }]
  const licensed = buildStory(build(t), t)
  assert.deepEqual(licensed.roadmap.find(h => h.key === 'later').items.find(i => i.key === 'mdi').controls.map(c => c.id), ['DR.4'])
  assert.ok(!licensed.asks.some(a => a.key === 'mdi'), 'no licensing ask for a telemetry-only gap')
  // With Defender for Identity as the only gap, the foundational controls all read E and nothing says otherwise.
  const m2 = build(p)
  for (const c of m2.controls) if (c.tier === 'foundational' && c.mark) Object.assign(c, { mark: 'E', pct: 100 })
  const only = buildStory(m2, p)
  assert.equal(only.drift.length, 0)
  assert.match(only.takeaways.posture, /^\d+ of \d+ foundational controls are enforced( \(\d+ on a small sample\))?\. None reads below the baseline\.$/)
  assert.ok(!only.watch.some(w => /foundational controls? reads? below enforced/.test(w.label)))
  assert.ok(only.roadmap.find(h => h.key === 'later').items.some(i => i.key === 'mdi'))
})
test('analytics rules and threat intelligence gaps are foundational gaps in Now, and vulnerability assessment stays in Next', () => {
  // Foundational since Oct 16, 2026: the standard rule set and threat intelligence ingestion are switched on at build.
  const p = quarterPack()
  const put = (id, rows) => { p.manifest.push({ ResultId: id, Status: 'OK', Rows: rows.length, ReadTimeUtc: '2026-10-12T10:00:00Z' }); p.results[id] = rows }
  // A workspace with no enabled analytics rule is the gap. The rule count is context and never the grade.
  put('DR.9', [{ Scope: 'All workspaces', Metric: 'Total rules', Value: 40 }, { Scope: 'All workspaces', Metric: 'Enabled rules', Value: 0 }, { Scope: 'w1', Metric: 'Total rules', Value: 40 }, { Scope: 'w1', Metric: 'Enabled rules', Value: 0 }])
  put('DR.7', [{ Indicators: 0 }])
  put('DR.5', [{ Scope: 'Azure VM', Onboarded: 88, Assessed: 40 }])
  const { m, s } = story(p)
  const tier = id => m.controls.find(c => c.id === id).tier
  assert.deepEqual([tier('DR.9'), tier('DR.7'), tier('DR.5')], ['foundational', 'foundational', 'defense'])
  assert.deepEqual(['DR.9', 'DR.7'].map(id => s.drift.some(c => c.id === id)), [true, true], 'both on the gaps panel')
  const now = s.roadmap.find(h => h.key === 'now').items.find(i => i.key === 'drift')
  assert.ok(now.controls.some(c => c.id === 'DR.9') && now.controls.some(c => c.id === 'DR.7'), 'both in Now as Atmosera\'s fix')
  assert.match(now.evidence, /analytics rules \(no enabled rule in the workspace\) and threat intelligence$/)
  const next = s.roadmap.find(h => h.key === 'next').items
  assert.ok(!next.some(i => i.controls.some(c => ['DR.9', 'DR.7'].includes(c.id))), 'neither sits in Next')
  assert.deepEqual([m.controls.find(c => c.id === 'DR.9').value, s.drift.find(c => c.id === 'DR.9').detail], ['Not in force', 'no enabled rule in the workspace'])
  // Many disabled rules with one enabled in every workspace is tuning, never a foundational gap.
  const q = JSON.parse(JSON.stringify(p))
  q.results['DR.9'] = [{ Scope: 'All workspaces', Metric: 'Total rules', Value: 386 }, { Scope: 'All workspaces', Metric: 'Enabled rules', Value: 3 }, { Scope: 'w1', Metric: 'Total rules', Value: 386 }, { Scope: 'w1', Metric: 'Enabled rules', Value: 3 }]
  const tuned = story(q)
  assert.equal(tuned.m.controls.find(c => c.id === 'DR.9').value, 'In force')
  assert.ok(!tuned.s.drift.some(c => c.id === 'DR.9') && !tuned.s.roadmap.some(h => h.items.some(i => i.controls.some(c => c.id === 'DR.9'))), 'no gap and no roadmap item')
  const va = next.find(i => i.key === 'vulnassess')
  assert.deepEqual([va.title, va.controls.map(c => c.id)], ['Vulnerability assessment coverage', ['DR.5']])
  assert.ok(!s.roadmap.some(h => h.items.some(i => i.key === 'detect')), 'the detect item is retired')
})
test('counts read as natural English', () => {
  const p = quarterPack()
  p.results['IA.1'] = [{ UserType: 'Member', UsersSignedIn: 194, UsersChallenged: 193 }]
  p.results['IA.2'] = [{ Bucket: 'Retiring: SMS or voice', DistinctUsers: 1 }]
  p.results['OUT.1'][0].TruePositive = 1
  p.results['OUT.4'] = [{ IncidentNumber: 1, Severity: 'High', Tactics: 'InitialAccess', ExfilOrImpactTactic: false }]
  const { s } = story(p)
  assert.equal(s.takeaways.summary.startsWith('The confirmed threat did not carry an exfiltration or impact tactic'), true)
  assert.equal(s.kpis[1].sub, 'Classified as a true positive by the SOC')
  assert.equal(s.asks[0].body, '1 user on text message or voice, which retire Feb 1, 2027 (Jul 1, 2027 for Global Administrators and external users).')
  assert.equal(s.takeaways.methods, 'Microsoft retires text message and voice sign-in on February 1, 2027 (July 1, 2027 for Global Administrators and external users). 1 user signed in with it in the last 30 days.')
  assert.ok(s.watch.every(w => !/^1$/.test(w.value) || !/^(members|users|devices|resources) /.test(w.label)), JSON.stringify(s.watch))
})
test('every control in the register has a value, never null', () => {
  const { s } = story(quarterPack())
  const rows = s.register.flatMap(r => [...r.foundational, ...r.defense])
  assert.ok(rows.length > 40)
  for (const c of rows) {
    assert.ok(c.valueText && !/null|undefined/.test(c.valueText), c.label)
    assert.ok(['E', 'P', 'N', '–', 'N/A'].includes(c.chip), c.label)
  }
  assert.ok(rows.some(c => c.valueText === 'Not gathered' && c.chip === '–'))
})
test('a win, headline or narrative at E that leaves resources out never says every, all or none, and the register counts the exceptions', () => {
  const p = quarterPack()
  const set = (id, rows) => { p.manifest = p.manifest.filter(r => r.ResultId !== id); p.manifest.push({ ResultId: id, Status: 'OK', Rows: rows.length, ReadTimeUtc: '2026-10-12T10:00:00Z' }); p.results[id] = rows }
  // MFA at sign-in (180 of 194) and secure transfer (41 of 42) already read E with exceptions in this pack.
  set('EW.10', [{ Machines: 70, WithinCadence: 68, OverduePatches: 2, AssessedWithin7d: 70 }])
  set('EW.1', [{ Scope: 'Azure VM', OSPlatform: 'WindowsServer2022', Devices: 89, Onboarded: 88, CanBeOnboarded: 1, SensorActive: 81 }])
  set('EW.1-GAPS', [{ Reason: 'Onboarded, sensor not active', Product: '', Devices: 7, Eligible: true, Covered: false, Onboarded: 7, CanBeOnboarded: 0, NotSeen: 0, Other: 0 }, { Reason: 'Not onboarded, no endpoint detection found', Product: '', Devices: 1, Eligible: true, Covered: false, Onboarded: 0, CanBeOnboarded: 1, NotSeen: 0, Other: 0 }])
  set('DP.2', [{ Vaults: 20, SoftDelete: 19, PurgeProtection: 19, RbacAuth: 19 }])
  set('DR.10', [{ Closed: 100, Documented: 97 }])
  set('DR.9', [{ Scope: 'All workspaces', Metric: 'Total rules', Value: 386 }, { Scope: 'All workspaces', Metric: 'Enabled rules', Value: 386 }])
  const { m, s } = story(p)
  const ABSOLUTE = /\b(every|all|none)\b/i
  const patch = s.wins.find(w => w.eyebrow === 'Patching')
  assert.deepEqual([patch.value, patch.sub], ['68 of 70', '2 machines carry a critical or security patch past the cadence at collection.'], 'never "No critical or security patch past the cadence"')
  const ratioWins = s.wins.filter(w => m.controls.some(c => c.source === w.source && c.exceptions > 0))
  assert.deepEqual(ratioWins.map(w => w.value), ['180 of 194', '68 of 70'])
  for (const w of ratioWins) assert.ok(!ABSOLUTE.test(`${w.label} ${w.sub}`), `${w.label} ${w.sub}`)
  for (const x of m.pillars) for (const t of [x.headline, x.headlineShort, x.narrative].filter(Boolean)) assert.ok(!ABSOLUTE.test(t), `${x.name}: ${t}`)
  // The register shows meeting the threshold and having no exceptions as different things.
  const rows = s.register.flatMap(r => [...r.foundational, ...r.defense])
  const row = re => rows.find(c => re.test(c.label))
  assert.deepEqual([row(/^Azure virtual machines reporting/).chip, row(/^Azure virtual machines reporting/).exceptionText], ['E', '1 exception'])
  assert.deepEqual([row(/^Operating system findings/).chip, row(/^Operating system findings/).exceptionText], ['E', '2 exceptions'])
  assert.deepEqual([row(/^Analytics rules/).chip, row(/^Analytics rules/).exceptionText], ['E', ''], 'a complete reading carries no count')
  for (const c of rows) assert.equal(!!c.exceptionText, c.chip === 'E' && c.good < c.total, `${c.label}: ${c.exceptionText}`)
  // Gaps and the roadmap carry only controls below E, so no exception count reaches them.
  const shown = [...s.drift.map(c => c.detail), ...s.roadmap.flatMap(h => h.items.flatMap(i => [i.evidence, ...i.controls.map(c => c.detail)]))]
  assert.ok(shown.length && shown.every(t => !/\bexceptions?\b/.test(t)), shown.find(t => /\bexceptions?\b/.test(t)))
})
test('the identity win names the evaluated population in a federated tenant', () => {
  const p = quarterPack()
  p.results['IA.1'] = [{ UserType: 'Member', UsersSignedIn: 194, UsersChallenged: 175, NoMfaOnlyUnevaluated: 10, FederatedMfaAtLeastOnce: 175, FederatedWithoutMfa: 0 }]
  p.manifest.push({ ResultId: 'IA.1-FEDERATION', Status: 'OK', Rows: 1, ReadTimeUtc: '2026-10-12T10:00:00Z' })
  p.results['IA.1-FEDERATION'] = [{ FederatedDomains: 1, ConfigsRead: 1, Provider: 'Okta', MfaBehavior: 'acceptIfMfaDoneByFederatedIdp' }]
  const { s } = story(p)
  const win = s.wins.find(w => w.area === 'identity')
  assert.equal(win.value, '175 of 184')
  assert.equal(win.sub, 'Members whose sign-ins in the last 30 days could be evaluated.')
  assert.equal(story(quarterPack()).s.wins.find(w => w.area === 'identity').sub, 'Members who signed in over the last 30 days.')
})
test('the confirmed threats takeaway counts the threats, adds the tactic line when known and stands without examples', () => {
  const withRows = flaggedOne => {
    const p = quarterPack()
    p.results['OUT.4'] = [
      { Severity: 'High', ExfilOrImpactTactic: flaggedOne, Threat: 'Log4j vulnerability exploit aka Log4Shell IP IOC', Tactics: flaggedOne ? 'CommandAndControl,Exfiltration' : 'CommandAndControl', Created: '2026-08-18' },
      { Severity: 'Medium', ExfilOrImpactTactic: false, Threat: 'Password spray attack against Microsoft Entra ID application', Tactics: 'CredentialAccess', Created: '2026-07-28' }
    ]
    return story(p)
  }
  const clean = withRows(false)
  assert.ok(clean.m.threats)
  assert.equal(clean.s.takeaways.threats, 'The SOC classified 2 alerts as true positives this quarter. Neither confirmed threat carried an exfiltration or impact tactic.')
  const flagged = withRows(true)
  assert.equal(flagged.m.alerts.flagged, 1)
  assert.equal(flagged.s.takeaways.threats, 'The SOC classified 2 alerts as true positives this quarter.')
  // A Collection tactic sets the collector flag but is not exfiltration or impact, so the count stays narrow.
  const p = quarterPack()
  p.results['OUT.4'] = [{ Severity: 'High', ExfilOrImpactTactic: true, Threat: 'Suspicious inbox rule created', Tactics: 'Collection', Created: '2026-08-18' }, { Severity: 'High', ExfilOrImpactTactic: false, Threat: 'Password spray attack', Tactics: 'CredentialAccess', Created: '2026-07-28' }]
  const collection = story(p)
  assert.deepEqual([collection.m.alerts.flagged, collection.m.alerts.flaggedScope], [0, 'exfiltration or impact'])
  assert.equal(collection.s.takeaways.summary, 'Neither confirmed threat carried an exfiltration or impact tactic, and secure score rose 6.1 points.')
  // Rows without tactics keep the flag count and name the wider scope on every surface.
  p.results['OUT.4'] = p.results['OUT.4'].map(({ Tactics, Threat, Created, ...r }) => r)
  const wide = story(p)
  assert.deepEqual([wide.m.alerts.flagged, wide.m.alerts.flaggedScope], [1, 'collection, exfiltration or impact'])
  assert.equal(wide.s.kpis[1].label, 'True positives whose alerts carried a collection, exfiltration or impact tactic')
  assert.ok(!/carried an exfiltration or impact tactic/.test(JSON.stringify([wide.s.kpis, wide.s.wins, wide.s.takeaways, wide.m.tiers, wide.m.headline])), 'the narrow wording never appears without tactics')
  const none = story(quarterPack())
  assert.equal(none.m.threats, null, 'rows without a title give no examples')
  assert.equal(none.s.takeaways.threats, 'The SOC classified 2 alerts as true positives this quarter. Neither confirmed threat carried an exfiltration or impact tactic.', 'the slide is built without the examples table, so the takeaway stands')
})
test('a reviewed impact record leads the takeaways, and a confirmed impact withdraws the tactic win', () => {
  const withImpact = (confirmed, truePositives = 2) => {
    const p = quarterPack()
    p.results['OUT.1'][0].TruePositive = truePositives
    p.results['OUT.4'] = [{ Severity: 'High', ExfilOrImpactTactic: false, Threat: 'Log4j vulnerability exploit aka Log4Shell IP IOC', Tactics: 'CommandAndControl', Created: '2026-08-18' }, { Severity: 'Medium', ExfilOrImpactTactic: false, Threat: 'Password spray attack', Tactics: 'CredentialAccess', Created: '2026-07-28' }]
    p.context = { Impact: { Confirmed: confirmed, Reviewed: '2026-10-10', Reference: 'CHG-123', WindowStart: '2026-07-01', WindowEnd: '2026-09-30' } }
    return story(p)
  }
  const clear = withImpact(0)
  assert.equal(clear.s.takeaways.summary, 'The reviewed investigation records confirm no data exposure or business impact, and secure score rose 6.1 points.')
  assert.equal(clear.s.takeaways.threats, 'The SOC classified 2 alerts as true positives this quarter. Neither confirmed threat carried an exfiltration or impact tactic. The reviewed investigation records confirm no data exposure or business impact.')
  assert.equal(clear.s.wins[0].label, 'confirmed threats carried an exfiltration or impact tactic', 'the tactic win stands beside a clean determination')
  const hit = withImpact(1)
  assert.equal(hit.s.takeaways.summary, 'The reviewed investigation records confirm data exposure or business impact from 1 of the 2 confirmed threats, and secure score rose 6.1 points.')
  assert.equal(hit.s.takeaways.threats, 'The SOC classified 2 alerts as true positives this quarter. The reviewed investigation records confirm data exposure or business impact from 1 of the 2 confirmed threats.')
  assert.ok(!hit.s.wins.some(w => w.area === 'threat'), 'a confirmed impact is no win')
  assert.equal(hit.s.kpis[1].value, '0 of 2', 'the tactic KPI still reports the recorded tactics')
  assert.equal(withImpact(1, 1).s.takeaways.threats, 'The SOC classified 1 alert as a true positive this quarter. The reviewed investigation records confirm data exposure or business impact from the confirmed threat.')
})
test('a median at the floor reads as nine in ten triaged and closed, never investigated or resolved, and names high severity alerts', () => {
  const p = quarterPack()
  p.results['OUT.2'][0].MedianCloseMin = 22; p.results['OUT.2-ANALYST'][0].MedianCloseMin = 22
  const { s } = story(p)
  assert.equal(s.speed.value, '22 min')
  assert.equal(s.speed.label, 'median time to close, high severity alerts')
  assert.equal(s.speed.sub, '208 alerts closed. Nine in ten triaged and closed within 36 min.')
  assert.equal(s.kpis[2].sub, 'Nine in ten triaged and closed within 36 min')
  assert.ok(!/investigated and resolved|resulted in/.test(JSON.stringify([s.kpis, s.wins, s.takeaways])), 'closure time and tactic flags never read as verified outcomes')
  assert.equal(s.kpis[2].label, 'Median time to close, high severity alerts')
})
test('MFA at sign-in and MFA at the admin portals below E together read as one gap outside the appendix', () => {
  const p = quarterPack()
  p.manifest.push({ ResultId: 'IA.1-ADMINPORTAL', Status: 'OK', Rows: 1, ReadTimeUtc: '2026-10-12T10:00:00Z' })
  p.results['IA.1-ADMINPORTAL'] = [{ UserType: 'Member', Users: 15, UsersChallenged: 12 }]
  p.results['IA.8-CA'] = [
    { Flow: 'MFA at sign-in', Control: 'IA.1', PolicyRead: true, PolicySource: 'Raw', PolicyState: 'Scoped', ScopeReason: 'Users', EnforcedPolicies: 1, ExcludedIdentities: 2, DetailRead: false },
    { Flow: 'Admin portals', Control: 'IA.1-ADMINPORTAL', PolicyRead: true, PolicySource: 'Raw', PolicyState: 'Scoped', ScopeReason: 'Users', EnforcedPolicies: 1, ExcludedIdentities: 1, DetailRead: false }
  ]
  const { m, s } = story(p)
  assert.ok(m.controls.find(c => c.id === 'IA.1').mark === 'P' && m.controls.find(c => c.id === 'IA.1-ADMINPORTAL').mark === 'P', 'both read below E')
  assert.equal(s.drift.filter(c => /^Multifactor authentication/.test(c.label)).length, 1, 'one MFA gap on the panel')
  const gap = s.drift.find(c => c.id === 'IA.1')
  assert.equal(gap.detail, '180 of 194 · admin portals 12 of 15')
  assert.deepEqual(gap.folded.map(c => c.id), ['IA.1-ADMINPORTAL'])
  assert.equal(s.driftControls.length, s.drift.length + 1, 'the counts still cover every control')
  assert.equal(s.watch.find(w => /foundational controls read below enforced/.test(w.label)).value, String(s.driftControls.length))
  assert.match(s.takeaways.posture, new RegExp(`${['no', 'one', 'two', 'three', 'four', 'five', 'six', 'seven'][s.driftControls.length]} read below the baseline`, 'i'))
  const now = s.roadmap.find(h => h.key === 'now').items.find(i => i.key === 'drift')
  assert.match(now.evidence, /^\d+ controls below the baseline: MFA at sign-in \(180 of 194 · admin portals 12 of 15\), /)
  assert.ok(!/admin portal MFA/.test(now.evidence), 'the roadmap names the MFA gap once')
  assert.ok(now.controls.some(c => c.id === 'IA.1-ADMINPORTAL'), 'the folded control still lands on the roadmap')
  // The register in the appendix keeps both rows.
  const identity = s.register.find(r => r.group === 'Identity and access')
  assert.equal(identity.foundational.filter(c => /^Multifactor authentication/.test(c.label) && c.chip === 'P').length, 2)
  // Below E at the admin portals alone is its own gap.
  p.results['IA.8-CA'][0].PolicyState = 'Enforced'
  assert.deepEqual(story(p).s.drift.filter(c => /^Multifactor authentication/.test(c.label)).map(c => c.id), ['IA.1-ADMINPORTAL'])
})
test('no roadmap evidence, ask or takeaway says scheduled, approved, completed, implemented or verified unless the matching Actions record is present', () => {
  const STATUS = /\b(scheduled|approved|completed|implemented|verified)\b/i
  // Every control below E, so every catalog item and ask is on the roadmap, beside the pack as collected.
  const everything = context => { const p = quarterPack(); p.context = context; const m = build(p); for (const c of m.controls) Object.assign(c, { mark: 'N', pct: 10, good: 1, total: 10, measured: true, na: false, value: '1 of 10', boolean: false }); return buildStory(m, p) }
  const collected = context => { const p = quarterPack(); p.context = context; return buildStory(build(p), p) }
  const strings = s => [
    // carries: the string that names the reviewed status when the item has a record. Ask titles and short labels never do.
    ...s.roadmap.flatMap(h => h.items.map(i => ({ key: i.key, action: i.action, carries: true, text: i.evidence }))),
    ...s.asks.flatMap(a => [[a.title, false], [a.body, true], [a.short, false]].map(([text, carries]) => ({ key: a.key, action: a.action, carries, text }))),
    ...Object.entries(s.takeaways).map(([key, text]) => ({ key: `takeaway:${key}`, action: null, carries: false, text })),
    { key: 'drift', action: s.roadmap[0].items.find(i => i.key === 'drift')?.action || null, carries: true, text: s.driftNote }
  ]
  // Without a context record nothing says an item is scheduled, approved or complete, and the rewritten lines read as recommendations.
  for (const s of [collected(null), everything(null)]) {
    for (const x of strings(s)) assert.ok(!STATUS.test(x.text), `${x.key}: ${x.text}`)
    assert.ok(!/schedules each fix|scoped and sequenced|on schedule|non-event/i.test(JSON.stringify(s)))
  }
  const plain = collected(null)
  assert.equal(plain.roadmap[0].items.find(i => i.key === 'critical').evidence, '7 critical exploitable findings. Atmosera recommends validating the affected workloads and agreeing remediation or compensating controls with the owners inside the patch cadence.')
  assert.equal(plain.driftNote, 'Below the baseline at collection. Atmosera recommends closing each gap first.')
  assert.equal(plain.takeaways.roadmap, 'Every control below enforced is proposed in one of three horizons, by risk and by what each needs from your team.')
  assert.match(plain.takeaways.decisions, /approval or access from your team to move the roadmap forward\.$/)
  // With a record for every item on the roadmap and every ask, each one carries its own status and nothing else does.
  const keys = [...new Set(strings(everything(null)).map(x => x.key).filter(k => !k.startsWith('takeaway:') && k !== 'other'))]
  assert.ok(keys.length >= 15, keys.join(', '))
  const record = (Key, Status) => ({ Key, Status, Owner: 'Client identity owner', TargetDate: '2026-12-15', Reference: `CHG-${Key}`, Reviewed: '2026-10-14', WindowStart: '2026-07-01', WindowEnd: '2026-09-30' })
  for (const [Status, word] of [['Approved', 'approved'], ['Scheduled', 'scheduled'], ['InProgress', 'in progress'], ['Verified', 'verified'], ['AwaitingApproval', 'awaiting approval'], ['PendingValidation', 'pending validation']]) {
    const delivered = Status === 'Verified' ? keys.map(k => ({ Title: k, Outcome: 'Done.', Reference: `CHG-${k}`, CompletedDate: '2026-09-15' })) : []
    const s = everything({ Actions: keys.map(k => record(k, Status)), Delivered: delivered })
    for (const x of strings(s)) {
      if (x.action && x.carries) {
        assert.ok(new RegExp(`\\b${word}\\b`, 'i').test(x.text), `${x.key} should carry ${word}: ${x.text}`)
        assert.ok(!STATUS.test(x.text.replace(new RegExp(`\\b${word}\\b`, 'gi'), '')), `${x.key} carries another status: ${x.text}`)
      } else assert.ok(!STATUS.test(x.text), `${x.key} carries a status it has no record for: ${x.text}`)
    }
  }
  // One record changes its own item only.
  const one = collected({ Actions: [record('critical', 'Scheduled')] })
  const critical = one.roadmap[0].items.find(i => i.key === 'critical')
  assert.equal(critical.evidence, '7 critical exploitable findings. Scheduled, owner Client identity owner, target Dec 15, 2026 (CHG-critical, reviewed Oct 14, 2026).')
  assert.equal(critical.action.key, 'critical')
  for (const x of strings(one).filter(x => x.key !== 'critical')) assert.ok(!STATUS.test(x.text), `${x.key}: ${x.text}`)
  assert.equal(one.driftNote, 'Below the baseline at collection. Atmosera recommends closing each gap first.')
  const drift = collected({ Actions: [record('drift', 'InProgress')] })
  assert.equal(drift.driftNote, 'Below the baseline at collection. Fixes in progress (CHG-drift).')
  const ask = collected({ Actions: [record('idp', 'AwaitingApproval')] }).asks.find(a => a.key === 'idp')
  assert.equal(ask.body, 'Sign-in and user risk policies for all users, with leaked credential response. Awaiting approval, owner Client identity owner, target Dec 15, 2026 (CHG-idp, reviewed Oct 14, 2026).')
  assert.equal(ask.title, 'Approve the user-risk policy', 'an ask still awaiting approval keeps its title')
  assert.equal(ask.bodyText, 'Sign-in and user risk policies for all users, with leaked credential response.')
})
test('an ask whose reviewed record settles the decision leaves the asks before the limit and the count, and its roadmap item keeps the status', () => {
  const record = (Key, Status) => ({ Key, Status, TargetDate: '2026-12-15', Reference: `CHG-${Key}`, Reviewed: '2026-10-12', WindowStart: '2026-07-01', WindowEnd: '2026-09-30' })
  // The quarter pack asks for methods, access, idp and segment. An open consent setting adds a Next horizon ask ahead
  // of segment, so segment is the fifth candidate and falls outside the four.
  const withConsent = actions => { const p = quarterPack(); p.manifest.push({ ResultId: 'IA.13', Status: 'OK', Rows: 1, ReadTimeUtc: '2026-10-12T10:00:00Z' }); p.results['IA.13'] = [{ UserConsent: 'Allowed', AdminConsentWorkflow: false, Governed: false }]; p.context = actions ? { Actions: actions } : null; return buildStory(build(p), p) }
  assert.deepEqual(withConsent(null).asks.map(a => a.key), ['methods', 'access', 'idp', 'consent'])
  for (const Status of ['Approved', 'Scheduled', 'InProgress']) {
    const s = withConsent([record('idp', Status)])
    assert.deepEqual(s.asks.map(a => a.key), ['methods', 'access', 'consent', 'segment'], `${Status} frees its slot for the pending segment ask`)
    assert.ok(!s.asks.some(a => a.title === 'Approve the user-risk policy'))
    assert.ok(!s.summaryAsks.some(a => /user-risk/.test(a.label)), 'the executive summary never asks for it either')
    assert.equal(s.takeaways.decisions, 'Four items need approval or access from your team to move the roadmap forward.')
    assert.deepEqual(s.settledAsks.map(a => a.key), ['idp'])
    assert.match(s.roadmap.flatMap(h => h.items).find(i => i.key === 'idp').evidence, new RegExp(`\\(CHG-idp, reviewed Oct 12, 2026\\)`), 'the roadmap item carries the status instead')
  }
  // Verified needs its Delivered record, and settles the ask the same way.
  const p = quarterPack(); p.context = { Actions: [record('methods', 'Verified'), record('segment', 'Verified')], Delivered: [{ Title: 'Method move', Outcome: 'Done.', Reference: 'CHG-methods', CompletedDate: '2026-09-20' }, { Title: 'Segmentation', Outcome: 'Done.', Reference: 'CHG-segment', CompletedDate: '2026-09-20' }] }
  const verified = buildStory(build(p), p)
  assert.deepEqual(verified.asks.map(a => a.key), ['access', 'idp'])
  assert.deepEqual(verified.summaryAsks.map(a => a.label), ['Approve the user-risk policy'])
  assert.equal(verified.takeaways.decisions, 'Two items need approval or access from your team to move the roadmap forward.')
  // A pending status keeps the ask, with its status.
  assert.deepEqual(withConsent([record('idp', 'PendingValidation')]).asks.map(a => a.key), ['methods', 'access', 'idp', 'consent'])
})
test('every roadmap item and ask key the story builds is a key the Actions record accepts', () => {
  const { ACTION_KEYS } = require('../report/report-model.js')
  const keys = new Set(['drift', 'critical', 'methods', 'access', ...CATALOG.map(e => e.key)])
  assert.deepEqual([...keys].sort(), [...ACTION_KEYS].sort())
})
test('a reviewed status on the read access ask never removes it, since no status shows the permission was provisioned', () => {
  // DP.8 could not be read for lack of permission, so the quarter pack asks for read access.
  const record = Status => ({ Key: 'access', Status, TargetDate: '2026-12-15', Reference: 'CHG-access', Reviewed: '2026-10-12', WindowStart: '2026-07-01', WindowEnd: '2026-09-30' })
  const only = actions => { const p = quarterPack(); p.context = actions ? { Actions: actions, Delivered: [{ Title: 'Access', Outcome: 'Granted.', Reference: 'CHG-access', CompletedDate: '2026-09-20' }] } : null; return buildStory(build(p), p) }
  const before = only(null).asks.map(a => a.key)
  assert.ok(before.includes('access'))
  for (const [Status, label] of [['Approved', 'Approved'], ['Scheduled', 'Scheduled'], ['InProgress', 'In progress'], ['Verified', 'Verified']]) {
    const s = only([record(Status)])
    assert.deepEqual(s.asks.map(a => a.key), before, `${Status} keeps the access ask and the rest in place`)
    assert.equal(s.asks.find(a => a.key === 'access').body, `Sharing settings. ${label}, target Dec 15, 2026 (CHG-access, reviewed Oct 12, 2026).`)
    assert.equal(s.takeaways.decisions, `${['', 'One', 'Two', 'Three', 'Four'][before.length]} ${before.length === 1 ? 'item needs' : 'items need'} approval or access from your team to move the roadmap forward.`)
    assert.deepEqual(s.settledAsks, [])
  }
})
