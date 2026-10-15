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
test('response speed never shows a median under the floor and uses the 90th percentile instead', () => {
  const { m, s } = story(quarterPack())
  assert.equal(m.timing.find(r => r.scope === 'High').median, null, 'the 7 minute median is below the floor')
  assert.equal(m.timing.find(r => r.scope === 'Medium').median.value, '3 hr')
  assert.equal(s.speed.value, '36 min')
  assert.match(s.takeaways.operations, /^615 alerts triaged this quarter\. 90% of high-severity alerts closed within 36 min\.$/)
  const text = JSON.stringify(s)
  assert.ok(!/\b7 min\b|\b8 min\b/.test(text), 'a sub-floor median leaked into the story')
  assert.ok(MEDIAN_FLOOR === 20)
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
  assert.deepEqual(s.kpis.map(k => k.value), ['615', '0 of 2', '36 min', '59.7%'])
  assert.deepEqual(s.kpis.map(k => k.label), ['Alerts triaged', 'True positives whose alerts carried an exfiltration or impact tactic', 'Time for 90% of high-severity alerts to close', 'Defender for Cloud secure score'])
  assert.equal(s.kpis[1].sub, 'Both classified as true positives by the SOC', 'a true positive is a classification, never an investigation or a closure')
  assert.equal(s.kpis[0].sub, 'Jul 1 to Sep 30, 2026', 'the alert KPI carries the period, not the detection count')
  assert.equal(s.kpis[3].sub, 'Up 6.1 points since Jul 2026, from 53.6%')
  assert.deepEqual(s.wins.map(w => w.eyebrow), ['Confirmed threats', 'Response speed', 'Posture', 'Identity', 'Patching', 'Email protection'])
  assert.deepEqual([s.wins[0].value, s.wins[0].label, s.wins[0].sub], ['0 of 2', 'confirmed threats carried an exfiltration or impact tactic', 'Both classified as true positives by the SOC this quarter.'])
  assert.equal(new Set(s.wins.map(w => w.area)).size, s.wins.length, 'at most one win per area')
  assert.equal(s.takeaways.summary, 'Neither confirmed threat carried an exfiltration or impact tactic, and secure score rose 6.1 points.')
  assert.match(s.takeaways.posture, /foundational controls are enforced\. (Two|Three|Four) read below the baseline and are first on the roadmap\./)
  assert.ok(!/\breached\b|no impact|did not reach|investigated/i.test(JSON.stringify(s)), 'an outcome verb or an unrecorded impact determination reached the story')
  const spoken = JSON.stringify([s.takeaways, s.roadmap.map(h => h.items.map(i => [i.title, i.evidence])), s.watch, s.wins, s.asks, s.summaryWins, s.matrix])
  assert.ok(!/\bdrift|at build|regress/i.test(spoken), 'the story never claims a regression or a build-time configuration')
  assert.ok(s.takeaways.pillars && s.takeaways.priorities, 'the grounding slides have takeaways')
  assert.deepEqual(s.drift.map(c => c.short).sort(), ['Key Vault purge protection', 'anonymous blob access', 'storage TLS 1.2'].sort())
  assert.deepEqual(s.asks.map(a => a.title), ['Move users off text message and voice MFA', 'Grant read access for one ungraded control', 'Approve the user-risk policy', 'Agree a segmentation design and change windows'])
  assert.equal(s.asks[1].body, 'Sharing settings.', 'only the permission gap is an access ask, not the service error')
  // The executive summary names the items that need action from the client. Read access is Atmosera's to arrange.
  assert.deepEqual(s.summaryAsks, [{ value: '40 users', label: 'need to update their MFA method before Feb 1, 2027' }, { value: '1 control', label: 'Approve the user-risk policy' }, { value: '2 controls', label: 'Agree a segmentation design and change windows' }])
  assert.ok(!/passwordless|passkey/i.test(JSON.stringify(s)), 'the story never frames the MFA method update as passwordless')
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
test('a foundational control that needs a license goes to Later with its ask, not into the foundational gaps', () => {
  const p = quarterPack()
  p.manifest.push({ ResultId: 'DR.11', Status: 'UNAVAILABLE', Rows: 0, ReadTimeUtc: '2026-10-12T10:00:00Z', AccessGap: false, NotOnboarded: true })
  p.manifest.push({ ResultId: 'NB.10', Status: 'OK', Rows: 1, ReadTimeUtc: '2026-10-12T10:00:00Z' })
  p.results['NB.10'] = [{ Scope: 'Azure VM', Devices: 3, Compliant: 0 }] // domain controllers in Azure, so the control applies
  const { s } = story(p)
  assert.ok(!s.drift.some(c => c.id === 'DR.11'))
  assert.deepEqual(s.licensed.map(c => c.id), ['DR.11'])
  const later = s.roadmap.find(h => h.key === 'later').items.find(i => i.key === 'mdi')
  assert.ok(later && later.controls[0].id === 'DR.11', 'Defender for Identity sits in Later')
  assert.ok(s.asks.some(a => a.title === 'Approve Defender for Identity licensing'))
  assert.ok(!s.asks.some(a => /read access/.test(a.title) && /Defender for Identity/.test(a.body)), 'never a read access ask')
  assert.match(s.takeaways.posture, /read below the baseline, (two|three|four) first on the roadmap and one waiting on licensing\./)
  assert.equal(s.watch.find(w => /foundational controls read below enforced/.test(w.label)).value, String(s.drift.length + 1))
  // With the licensed control as the only foundational gap, nothing claims that every foundational control reads E.
  const m2 = build(p)
  for (const c of m2.controls) if (c.tier === 'foundational' && c.mark && c.id !== 'DR.11') Object.assign(c, { mark: 'E', pct: 100 })
  const only = buildStory(m2, p)
  assert.deepEqual([only.drift.length, only.licensed.length], [0, 1])
  assert.match(only.takeaways.posture, /^\d+ of \d+ foundational controls are enforced\. One reads below the baseline, one waiting on licensing\.$/)
  assert.equal(only.watch.find(w => /foundational control reads below enforced/.test(w.label)).value, '1')
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
  assert.equal(s.asks[0].body, '1 user needs to update their MFA method before February 1, 2027, when Microsoft retires text message and voice sign-in.')
  assert.equal(s.takeaways.methods, 'Microsoft retires text message and voice sign-in on February 1, 2027. 1 user still relies on it.')
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
test('the confirmed threats takeaway counts the threats, adds the exfiltration line when known and is empty without examples', () => {
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
  assert.equal(none.s.takeaways.threats, '')
})
test('a reviewed impact record leads the takeaways, and a confirmed impact withdraws the tactic win', () => {
  const withImpact = (confirmed, truePositives = 2) => {
    const p = quarterPack()
    p.results['OUT.1'][0].TruePositive = truePositives
    p.results['OUT.4'] = [{ Severity: 'High', ExfilOrImpactTactic: false, Threat: 'Log4j vulnerability exploit aka Log4Shell IP IOC', Tactics: 'CommandAndControl', Created: '2026-08-18' }, { Severity: 'Medium', ExfilOrImpactTactic: false, Threat: 'Password spray attack', Tactics: 'CredentialAccess', Created: '2026-07-28' }]
    p.context = { Impact: { Confirmed: confirmed, Reviewed: '2026-10-10', Reference: 'CHG-123' } }
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
