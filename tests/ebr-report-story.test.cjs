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
  put('OUT.4', [{ IncidentNumber: 1, Severity: 'High', ExfilOrImpactTactic: false }, { IncidentNumber: 2, Severity: 'High', ExfilOrImpactTactic: false }])
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
  assert.deepEqual(s.wins.map(w => w.eyebrow), ['Threat outcomes', 'Response speed', 'Posture', 'Identity', 'Patching', 'Email protection'])
  assert.equal(new Set(s.wins.map(w => w.area)).size, s.wins.length, 'at most one win per area')
  assert.equal(s.takeaways.summary, 'Neither confirmed threat reached exfiltration or impact, and secure score rose 6.1 points.')
  assert.match(s.takeaways.posture, /foundational controls are enforced\. (Two|Three|Four) have drifted and are first on the roadmap\./)
  assert.deepEqual(s.drift.map(c => c.short).sort(), ['Key Vault purge protection', 'anonymous blob access', 'storage TLS 1.2'].sort())
  assert.deepEqual(s.asks.map(a => a.title), ['Approve a passkey change window', 'Grant read access for one ungraded control', 'Approve the user-risk policy', 'Agree a segmentation design and change windows'])
  assert.equal(s.asks[1].body, 'Sharing settings.', 'only the permission gap is an access ask, not the service error')
  assert.equal(s.deadlineDays, 112)
  const all = JSON.stringify(s)
  assert.ok(!/;|→|←|\bcontain(ed|ment)\b|\(null\)|\bincidents?\b/i.test(all.replace(/\\u[0-9a-f]{4}/gi, '')), all.match(/.{0,40}(;|contain|\(null\)|incident).{0,40}/i)?.[0])
})
test('counts read as natural English', () => {
  const p = quarterPack()
  p.results['IA.1'] = [{ UserType: 'Member', UsersSignedIn: 194, UsersChallenged: 193 }]
  p.results['IA.2'] = [{ Bucket: 'Retiring: SMS or voice', DistinctUsers: 1 }]
  p.results['OUT.1'][0].TruePositive = 1
  p.results['OUT.4'] = [{ IncidentNumber: 1, Severity: 'High', ExfilOrImpactTactic: false }]
  const { s } = story(p)
  assert.equal(s.takeaways.summary.startsWith('The confirmed threat did not reach exfiltration or impact'), true)
  assert.equal(s.asks[0].body, 'Moves 1 text message and voice user before February 1, 2027.')
  assert.equal(s.takeaways.passwordless, 'Microsoft retires text message and voice sign-in on February 1, 2027. 1 user still relies on it.')
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
      { Severity: 'High', ExfilOrImpactTactic: flaggedOne, Threat: 'Log4j vulnerability exploit aka Log4Shell IP IOC', Tactics: 'CommandAndControl', Created: '2026-08-18' },
      { Severity: 'Medium', ExfilOrImpactTactic: false, Threat: 'Password spray attack against Microsoft Entra ID application', Tactics: 'CredentialAccess', Created: '2026-07-28' }
    ]
    return story(p)
  }
  const clean = withRows(false)
  assert.ok(clean.m.threats)
  assert.equal(clean.s.takeaways.threats, '2 confirmed threats were investigated and closed. Neither confirmed threat reached exfiltration or impact.')
  const flagged = withRows(true)
  assert.equal(flagged.m.alerts.flagged, 1)
  assert.equal(flagged.s.takeaways.threats, '2 confirmed threats were investigated and closed.')
  const none = story(quarterPack())
  assert.equal(none.m.threats, null, 'rows without a title give no examples')
  assert.equal(none.s.takeaways.threats, '')
})
