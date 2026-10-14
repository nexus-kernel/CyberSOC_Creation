/* The story behind the EBR deck, derived from the report model: outcome KPIs, wins, the watch list,
   decisions needed, foundational drift, the posture matrix, the Now, Next and Later roadmap and the
   takeaway subtitles. Pure, so the HTML can adopt it later. Rules are in
   docs/plans/2026-10-12-ebr-deck-restructure-design.md.

   Copy rules hold here too: alerts not incidents, no semicolons or arrows, open alert counts and
   severity increases never appear (they stay in the presenter notes), medians under the 20 minute
   floor are never shown, and containment is never claimed. */
(function (root) {
  'use strict'
  const R = typeof module !== 'undefined' && module.exports ? require('./report-model.js') : root.EbrReport
  const { fmt, clean, pctText, plural, MEDIAN_FLOOR, E_THRESHOLD, RETIREMENT } = R
  const WORDS = ['no', 'one', 'two', 'three', 'four', 'five', 'six', 'seven', 'eight', 'nine', 'ten']
  const word = n => n >= 0 && n < WORDS.length ? WORDS[n] : fmt(n)
  const GROUPS = ['Identity and access', 'Endpoint and workload', 'Network and boundary', 'Data protection', 'Detection and response']
  const isoDay = v => String(v ?? '').slice(0, 10)
  const days = (from, to) => /^\d{4}-\d{2}-\d{2}$/.test(isoDay(from)) && /^\d{4}-\d{2}-\d{2}$/.test(isoDay(to)) ? Math.round((Date.parse(isoDay(to)) - Date.parse(isoDay(from))) / 864e5) : null
  const shortDate = v => /^\d{4}-\d{2}-\d{2}$/.test(isoDay(v)) ? new Date(isoDay(v) + 'T12:00:00Z').toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric', timeZone: 'UTC' }) : ''
  const list = items => items.length <= 1 ? items.join('') : `${items.slice(0, -1).join(', ')} and ${items[items.length - 1]}`
  const sentence = text => { const t = clean(text); return t ? t.charAt(0).toUpperCase() + t.slice(1) : '' }

  // Short names for the controls, used in grouped roadmap items, the drift panel and the asks.
  const SHORT = [
    [/^Multifactor authentication required at sign-in/, 'MFA at sign-in'], [/^Location-based sign-in/, 'location-based sign-in controls'],
    [/^Legacy authentication/, 'legacy authentication blocking'], [/^Anti-phishing policy applied/, 'anti-phishing policy'],
    [/^Multifactor authentication at admin portal/, 'admin portal MFA'], [/^Device code flow/, 'device code blocking'],
    [/^Advanced anti-phishing/, 'advanced anti-phishing'], [/^Privileged roles/, 'PIM eligibility'], [/^Identity Protection/, 'user and sign-in risk policies'],
    [/^Application consent/, 'app consent workflow'], [/^Endpoint detection and response/, 'endpoint detection'], [/^Azure virtual machines reporting/, 'Azure VM onboarding'],
    [/^Real-time anti-malware/, 'real-time anti-malware'], [/^Tamper protection/, 'tamper protection'], [/^Host firewall/, 'host firewall'],
    [/^Operating system findings/, 'patch cadence'], [/^Vulnerability assessment/, 'vulnerability assessment'], [/^Platform integrity/, 'Trusted Launch'],
    [/^Encryption at host/, 'encryption at host'], [/^Credential protection/, 'credential protection'], [/^Remote Desktop/, 'RDP hardening'],
    [/^Application allow-listing/, 'Intune app control'], [/^Encryption in transit/, 'HTTPS-only web apps'], [/^Transport encryption enforced on Azure SQL/, 'Azure SQL TLS'],
    [/^App Service minimum TLS/, 'App Service TLS 1.2'], [/^Anonymous blob access/, 'anonymous blob access'], [/^Network protection/, 'network protection'],
    [/^Workload subnets/, 'subnet segmentation'], [/^Storage accounts closed to public/, 'storage public network access'], [/^Blob containers closed/, 'public blob containers'],
    [/^Directory traffic/, 'directory signing'], [/^NTLMv2/, 'NTLMv2'], [/^Secure transfer/, 'storage secure transfer'], [/^Storage minimum TLS/, 'storage TLS 1.2'],
    [/^Key Vault soft delete/, 'Key Vault soft delete'], [/^Key Vault purge/, 'Key Vault purge protection'], [/^Key Vault access governed/, 'Key Vault RBAC'],
    [/^Managed disks/, 'disk encryption at rest'], [/^Safe Links/, 'Safe Links'], [/^Safe Attachments/, 'Safe Attachments'], [/^Malicious mail removed/, 'post-delivery removal'],
    [/^Zero-hour auto purge/, 'zero-hour auto purge'], [/^Collaboration sharing/, 'sharing settings'], [/^Endpoint disk encryption/, 'endpoint disk encryption'],
    [/^Azure Backup/, 'VM backup'], [/^Endpoint sensors active/, 'endpoint sensors'], [/^Cloud workload protection/, 'workload protection'],
    [/^Domain controller telemetry/, 'domain controller telemetry'], [/^Alerts closed with a documented/, 'documented dispositions'], [/^Defender for Identity sensors/, 'Defender for Identity sensors'],
    [/^Audit logging initiative/, 'audit logging initiative'], [/^Analytics rules/, 'analytics rules'], [/^Threat intelligence/, 'threat intelligence'], [/^Diagnostic logging/, 'diagnostic logging']
  ]
  const short = c => (SHORT.find(([re]) => re.test(c.label)) || [null, c.label.charAt(0).toLowerCase() + c.label.slice(1)])[1]

  // Roadmap catalog for defense in depth controls (foundational controls below E are drift and go to Now).
  // Horizons follow the "why it waits" column of the controls baseline: Next needs configuration or an
  // approval, Later needs a maintenance window, a design change or licensing. Every below-E control
  // must match an item here (tests/ebr-report-story.test.cjs enforces it).
  const CATALOG = [
    { key: 'idp', horizon: 'next', title: 'Identity Protection user risk', match: /^Identity Protection/, ask: { title: 'Approve the user-risk policy', body: 'Sign-in and user risk policies for all users, with leaked credential response.' } },
    { key: 'phish', horizon: 'next', title: 'Advanced anti-phishing', match: /^Advanced anti-phishing/ },
    { key: 'consent', horizon: 'next', title: 'Application consent governance', match: /^Application consent/, ask: { title: 'Approve the admin consent workflow', body: 'Users request app consent and an administrator approves it.' } },
    { key: 'workload', horizon: 'next', title: 'Workload protection scope', match: /^Cloud workload protection/, priority: 'DR.2' },
    { key: 'logging', horizon: 'next', title: 'Diagnostic logging', match: /^(Diagnostic logging|Audit logging initiative)/, priority: 'DR.13' },
    { key: 'kvrbac', horizon: 'next', title: 'Key Vault access model', match: /^Key Vault access governed/ },
    { key: 'diskenc', horizon: 'next', title: 'Endpoint disk encryption', match: /^Endpoint disk encryption/ },
    { key: 'containers', horizon: 'next', title: 'Public blob containers', match: /^Blob containers closed/, ask: { title: 'Confirm which public containers are intended', body: 'Containers set to public access are made private unless they serve public content by design.' } },
    { key: 'detect', horizon: 'next', title: 'Detection content', match: /^(Analytics rules|Threat intelligence|Vulnerability assessment)/ },
    { key: 'segment', horizon: 'later', title: 'Network segmentation and exposure', match: /^(Workload subnets|Storage accounts closed to public)/, priority: 'NB.1', ask: { title: 'Agree a segmentation design and change windows', body: 'Network security groups or firewall routes on every workload subnet, and private access for storage.' } },
    { key: 'windows', horizon: 'later', title: 'Windows protocol hardening', match: /^(Remote Desktop|NTLMv2|Directory traffic|Credential protection)/ },
    { key: 'backup', horizon: 'later', title: 'Backup coverage', match: /^Azure Backup/, priority: 'DP.5b', ask: { title: 'Agree which machines persist and approve backup cost', body: 'Azure Backup on every persistent virtual machine, with pooled session hosts excluded by agreement.' } },
    { key: 'vmplatform', horizon: 'later', title: 'Encryption at host and Trusted Launch', match: /^(Encryption at host|Platform integrity)/ },
    { key: 'pim', horizon: 'later', title: 'Privileged role eligibility', match: /^Privileged roles/ },
    { key: 'allowlist', horizon: 'later', title: 'Application allow-listing', match: /^Application allow-listing/ },
    { key: 'sharing', horizon: 'later', title: 'Collaboration sharing boundaries', match: /^Collaboration sharing/ }
  ]
  const HORIZONS = [
    { key: 'now', label: 'Now', when: 'Next 30 days' },
    { key: 'next', label: 'Next', when: 'This quarter' },
    { key: 'later', label: 'Later', when: 'Needs scheduling or licensing' }
  ]

  function buildStory(m, data = {}) {
    const p = data.parameters || {}
    const below = c => !!c.mark && c.mark !== 'E'
    const ungathered = c => c.measured === false && !c.na
    const ratio = c => c.mark && !c.boolean && c.good !== null && c.total !== null
    const find = re => m.controls.find(c => re.test(c.label))
    const ofText = c => `${fmt(c.good)} of ${fmt(c.total)}`
    const valueText = c => c.na ? 'N/A' : ungathered(c) ? 'Not gathered' : c.boolean ? c.value : c.total > 9999 ? pctText(c.pct) : c.value
    // Copies of controls carry valueText in place of the model's value, so no story field reads (null).
    const safe = c => ({ ...c, value: valueText(c), valueText: valueText(c), short: short(c) })
    const s = { groups: GROUPS, horizons: HORIZONS }

    // Period. A calendar quarter gets a label, and "this quarter" in the takeaways.
    const start = isoDay(m.period.start), end = isoDay(m.period.end)
    const qStart = /^\d{4}-(01|04|07|10)-01$/.test(start), q = qStart ? (Number(start.slice(5, 7)) + 2) / 3 : null
    const qEnd = q ? `${start.slice(0, 4)}-${String(q * 3).padStart(2, '0')}` : null
    s.quarter = q && m.period.months === 3 && end.startsWith(qEnd) ? `Q${q} ${start.slice(0, 4)}` : null
    s.periodPhrase = s.quarter ? 'this quarter' : m.period.valid ? `from ${m.period.label}` : 'in the period'
    s.readShort = shortDate(p.PostureReadDate) || m.readDate

    // Response speed. A median shows only at the floor or above. Otherwise the 90th percentile carries
    // the story when it is within one hour.
    const timing = m.timing || []
    const speedRow = timing.find(r => r.scope === 'High') && timing.find(r => r.scope === 'High').n >= 5 ? timing.find(r => r.scope === 'High') : timing.find(r => r.scope === 'All')
    s.speed = null
    if (speedRow) {
      const who = speedRow.scope === 'High' ? 'high-severity alerts' : 'alerts'
      if (speedRow.median) s.speed = { value: speedRow.median.value, label: `median time to close, ${speedRow.scope === 'High' ? 'high severity' : 'all severities'}`, sub: `${plural(speedRow.n, 'alert', 'alerts')} closed${speedRow.p90 && speedRow.p90.minutes <= 60 ? `. 90% within ${speedRow.p90.value}` : ''}.`, line: `${sentence(who)} closed in a median of ${speedRow.median.value}.`, row: speedRow }
      else if (speedRow.p90 && speedRow.p90.minutes <= 60) s.speed = { value: speedRow.p90.value, label: `time for 90% of ${who} to close`, sub: `${plural(speedRow.n, 'alert', 'alerts')} closed ${s.periodPhrase}.`, line: `90% of ${who} closed within ${speedRow.p90.value}.`, row: speedRow }
    }

    // Score movement. Only a gain is a headline. A decline stays with the presenter notes.
    const score = m.tenantScore || m.cloudScore
    const scoreName = m.tenantScore ? 'Microsoft Secure Score' : 'Defender for Cloud secure score'
    const gain = score && score.delta && score.delta.points > 0 ? score.delta : null
    const firstPct = m.cloudScore && gain && !m.tenantScore ? m.cloudScore.trend[0]?.pct : null

    // Drift and controls.
    const measured = tier => m.controls.filter(c => c.tier === tier && c.mark)
    const enforced = tier => measured(tier).filter(c => c.mark === 'E')
    s.drift = m.controls.filter(c => c.tier === 'foundational' && below(c)).map(safe)
    s.ungathered = m.controls.filter(ungathered).map(safe)
    s.foundational = { enforced: enforced('foundational').length, measured: measured('foundational').length }
    s.defense = { enforced: enforced('defense').length, measured: measured('defense').length }

    // Outcome KPIs: alerts, impact, speed, score. Scope figures such as resources assessed are inputs, not outcomes.
    const kpis = []
    if (m.alerts) kpis.push({ value: fmt(m.alerts.triaged), label: 'Alerts triaged', sub: m.detections ? `${plural(m.detections.total, 'detection', 'detections')} correlated` : m.period.label, area: 'alerts' })
    if (m.alerts && m.alerts.flaggedKnown && m.alerts.truePositives > 0) kpis.push({ value: `${fmt(m.alerts.flagged)} of ${fmt(m.alerts.truePositives)}`, label: 'Confirmed threats with exfiltration or impact', sub: m.alerts.truePositives === 1 ? 'Investigated and closed' : `${m.alerts.truePositives === 2 ? 'Both' : 'All'} investigated and closed`, area: 'threat' })
    else if (m.alerts && m.alerts.truePositives !== null) kpis.push({ value: fmt(m.alerts.truePositives), label: 'Confirmed threats investigated', sub: 'Each closed to a documented disposition', area: 'threat' })
    if (s.speed) kpis.push({ value: s.speed.value, label: sentence(s.speed.label), sub: s.speed.sub.replace(/\.$/, ''), area: 'response' })
    if (score) kpis.push({ value: pctText(score.value), label: scoreName, sub: gain ? `Up ${fmt(gain.points)} points since ${gain.since}` : `Read ${s.readShort}`, area: 'posture' })
    if (kpis.length < 4 && s.foundational.measured) kpis.push({ value: `${fmt(s.foundational.enforced)} of ${fmt(s.foundational.measured)}`, label: 'Foundational controls enforced', sub: 'Across five pillars', area: 'controls' })
    s.kpis = kpis.slice(0, 4)

    // Wins, at most one per area, up to six.
    const winAt = (re, area, label, sub) => { const c = find(re); return c && c.mark === 'E' && c.pct !== null ? { area, value: c.boolean ? c.value : ofText(c), label, sub: c.population || sub, source: c.source } : null }
    const candidates = [
      m.alerts && m.alerts.flaggedKnown && m.alerts.truePositives > 0 && m.alerts.flagged === 0 ? { area: 'threat', eyebrow: 'Threat outcomes', value: `0 of ${fmt(m.alerts.truePositives)}`, label: m.alerts.truePositives === 1 ? 'confirmed threat reached exfiltration or impact' : 'confirmed threats reached exfiltration or impact', sub: `${m.alerts.truePositives === 1 ? 'Investigated and closed' : `${m.alerts.truePositives === 2 ? 'Both' : 'All'} investigated and closed`} by the SOC ${s.periodPhrase}.`, source: m.alerts.source } : null,
      s.speed ? { area: 'response', eyebrow: 'Response speed', value: s.speed.value, label: s.speed.label, sub: s.speed.sub, source: s.speed.row.source } : null,
      gain ? { area: 'posture', eyebrow: 'Posture', value: `+${fmt(gain.points)} pts`, label: firstPct !== null && firstPct !== undefined ? `secure score, ${pctText(firstPct)} in ${gain.since} to ${pctText(score.value)}` : `${scoreName} since ${gain.since}`, sub: score.note, source: score.source } : null,
      winAt(/^Multifactor authentication required at sign-in/, 'identity', 'users challenged for MFA at sign-in', 'Members who signed in over the last 30 days.'),
      winAt(/^Operating system findings/, 'endpoint', 'machines patched inside the agreed cadence', 'No critical or security patch past the cadence at collection.') || winAt(/^Endpoint detection and response/, 'endpoint', 'devices reporting to endpoint detection', 'Seen in the last 30 days.'),
      m.mailRemoved > 0 && find(/^Malicious mail removed/)?.mark === 'E' ? { area: 'data', eyebrow: 'Email protection', value: fmt(m.mailRemoved), label: 'malicious messages removed after delivery', sub: 'Zero-hour auto purge and automated remediation, last 30 days.', source: find(/^Malicious mail removed/).source } : winAt(/^Managed disks/, 'data', 'managed disks encrypted at rest', 'Platform or customer managed keys, at collection.'),
      winAt(/^Alerts closed with a documented/, 'detection', 'alerts closed with a documented disposition', 'Classification and closing comment, last 30 days.'),
      winAt(/^Encryption in transit/, 'network', 'published web apps enforcing HTTPS only', 'At collection.')
    ].filter(Boolean)
    const EYEBROW = { identity: 'Identity', endpoint: 'Endpoint', data: 'Data protection', detection: 'Detection', network: 'Network' }
    s.wins = candidates.slice(0, 6).map(w => ({ ...w, eyebrow: w.eyebrow || (w.label.startsWith('machines patched') ? 'Patching' : EYEBROW[w.area]) }))

    // The roadmap: every below-E control mapped to a catalog item, drift first in Now.
    const items = { now: [], next: [], later: [] }
    const prio = id => m.priorities.find(x => x.id === id)
    if (s.drift.length) items.now.push({ key: 'drift', title: 'Close foundational drift', evidence: `${plural(s.drift.length, 'control', 'controls')}: ${list(s.drift.map(c => c.short))}`, controls: s.drift, owner: 'Atmosera' })
    const crit = prio('BKL.1')
    if (m.criticalCves > 0) items.now.push({ key: 'critical', title: 'Critical vulnerability remediation', evidence: `${plural(m.criticalCves, 'critical exploitable finding', 'critical exploitable findings')}, scheduled with owners inside the patch cadence`, controls: [], priority: crit })
    const pw = m.passwordless && m.passwordless.retiring > 0 ? m.passwordless : null
    s.deadlineDays = days(p.PostureReadDate, RETIREMENT.date)
    s.deadlineShort = shortDate(RETIREMENT.date)
    if (pw) items[s.deadlineDays !== null && s.deadlineDays <= 180 ? 'now' : 'next'].push({ key: 'passkeys', title: 'Passkeys, first wave', evidence: `${plural(pw.retiring, 'user', 'users')} on text message or voice, ahead of ${shortDate(RETIREMENT.date)}`, controls: [], priority: prio('IA.2') })
    const mapped = new Set(s.drift.map(c => c.label))
    const other = []
    for (const c of m.controls.filter(c => below(c) && !mapped.has(c.label))) {
      const entry = CATALOG.find(e => e.match.test(c.label))
      if (!entry) { other.push(c); continue }
      let item = items[entry.horizon].find(i => i.key === entry.key)
      if (!item) { item = { key: entry.key, title: entry.title, controls: [], priority: entry.priority ? prio(entry.priority) : null, ask: entry.ask }; items[entry.horizon].push(item) }
      item.controls.push(safe(c))
      mapped.add(c.label)
    }
    // Priorities with no below-E control behind them (AI resources outside workload protection, for example) still belong on the roadmap.
    for (const pr of m.priorities.filter(x => ['DR.2', 'DR.13', 'DR.6'].includes(x.id))) {
      const entry = CATALOG.find(e => e.priority === pr.id || (pr.id === 'DR.6' && e.key === 'logging'))
      if (entry && !items[entry.horizon].some(i => i.key === entry.key) && !s.drift.some(c => entry.match.test(c.label))) items[entry.horizon].push({ key: entry.key, title: entry.title, controls: [], priority: pr })
    }
    if (other.length) items.next.push({ key: 'other', title: 'Other controls', controls: other.map(safe) })
    const evidenceOf = item => item.evidence || (item.controls.length === 1 && item.priority ? item.priority.evidence
      : item.controls.length === 1 && item.controls[0].boolean && item.controls[0].note ? item.controls[0].note
      : item.controls.length ? item.controls.map(c => `${sentence(c.short)} ${c.valueText}`).join(' · ') : item.priority ? item.priority.evidence : '')
    s.roadmap = HORIZONS.map(h => ({ ...h, items: items[h.key].map(i => ({ ...i, evidence: clean(evidenceOf(i)) })) }))
    s.unmapped = other.map(c => c.label)
    const headroom = m.posture && m.posture.scoreControls ? m.posture.scoreControls.filter(c => /vulnerabilit|security configuration/i.test(c.label)) : []
    const available = m.cloudScore ? Number((m.cloudScore.max - m.cloudScore.current).toFixed(2)) : null
    s.headroom = headroom.length && available ? `Vulnerability and configuration remediation hold ${fmt(Number(headroom.reduce((n, c) => n + c.remaining, 0).toFixed(2)))} of the ${fmt(available)} secure score points still available.` : ''

    // Decisions needed: passkey window, read access, then approvals for items whose controls read N.
    const asks = []
    if (pw) asks.push({ lead: plural(pw.retiring, 'user', 'users'), title: 'Approve a passkey change window', body: `Moves ${plural(pw.retiring, 'text message and voice user', 'text message and voice users')} before ${RETIREMENT.label}.`, short: `Approve a passkey change window before ${shortDate(RETIREMENT.date)}` })
    // Read access is asked for only where the collector was not permitted to read the evidence. Service
    // errors and packs that only need recollection are Atmosera's to resolve.
    const gap = id => (data.manifest || []).some(r => r.ResultId === id && (r.AccessGap === true || String(r.AccessGap).toLowerCase() === 'true'))
    const unread = s.ungathered.filter(c => gap(c.id))
    if (unread.length) asks.push({ lead: plural(unread.length, 'control', 'controls'), title: `Grant read access for ${unread.length === 1 ? 'one ungraded control' : `${word(unread.length)} ungraded controls`}`, body: `${sentence(list(unread.map(short)))}.`, short: 'Grant the read access needed to grade them' })
    for (const h of HORIZONS) for (const item of items[h.key]) {
      const entry = CATALOG.find(e => e.key === item.key)
      if (asks.length < 4 && entry && entry.ask && item.controls.some(c => c.mark === 'N')) asks.push({ lead: plural(item.controls.length, 'control', 'controls'), title: entry.ask.title, body: entry.ask.body, short: entry.ask.title })
    }
    s.asks = asks.slice(0, 4)

    // Executive summary columns. Wins and watch items avoid numbers already in the KPI strip.
    const kpiAreas = new Set(s.kpis.map(k => k.area))
    s.summaryWins = [
      s.foundational.measured && !kpiAreas.has('controls') ? { value: `${fmt(s.foundational.enforced)} of ${fmt(s.foundational.measured)}`, label: 'foundational controls enforced across five pillars' } : null,
      ...s.wins.filter(w => !kpiAreas.has(w.area)).map(w => ({ value: w.value, label: w.label + (/last 30 days/.test(w.sub) ? ', last 30 days' : '') }))
    ].filter(Boolean).slice(0, 3)
    const watch = []
    if (m.criticalCves > 0) watch.push({ value: fmt(m.criticalCves), label: m.criticalCves === 1 ? 'critical exploitable vulnerability open' : 'critical exploitable vulnerabilities open' })
    if (s.drift.length) watch.push({ value: fmt(s.drift.length), label: s.drift.length === 1 ? 'foundational control has drifted below enforced' : 'foundational controls have drifted below enforced' })
    const singular = label => [['Members', 'Member'], ['Users', 'User'], ['Devices', 'Device'], ['AI service resources', 'AI service resource'], ['Resources', 'Resource'], ['Virtual machines', 'Virtual machine'], ['Workload subnets', 'Workload subnet'], ['Key Vaults', 'Key Vault'], ['Storage accounts', 'Storage account'], ['Critical exploitable findings', 'Critical exploitable finding']].reduce((l, [many, one]) => l.startsWith(many + ' ') ? one + l.slice(many.length) : l, label)
    for (const h of (m.hardening || []).filter(x => x.rank < 99 && !['BKL.1', 'IA.2'].includes(x.id))) {
      const label = h.value === 1 ? singular(h.label) : h.label
      if (watch.length < 3) watch.push({ value: fmt(h.value), label: label.charAt(0).toLowerCase() + label.slice(1) })
    }
    s.watch = watch.slice(0, 3)
    s.summaryAsks = s.asks.slice(0, 3).map(a => ({ value: a.lead, label: a.short }))

    // Posture matrix: per pillar, foundational and defense in depth counts and a headline measure.
    const LEADS = { 'Identity and access': [/^Multifactor authentication required at sign-in/, /^Multifactor authentication at admin portal/], 'Endpoint and workload': [/^Endpoint detection and response/, /^Operating system findings/], 'Network and boundary': [/^Encryption in transit/, /^Workload subnets/], 'Data protection': [/^Managed disks/, /^Secure transfer/], 'Detection and response': [/^Alerts closed with a documented/, /^Analytics rules/] }
    const UNIT = { 'MFA at sign-in': 'users on MFA at sign-in', 'admin portal MFA': 'admins on MFA', 'endpoint detection': 'devices on EDR', 'patch cadence': 'patched in cadence', 'HTTPS-only web apps': 'web apps HTTPS-only', 'subnet segmentation': 'subnets segmented', 'disk encryption at rest': 'disks encrypted at rest', 'storage secure transfer': 'with secure transfer', 'documented dispositions': 'closures documented', 'analytics rules': 'rules enabled' }
    s.matrix = GROUPS.map(g => {
      const inG = m.controls.filter(c => c.group === g)
      const tierCount = t => { const ms = inG.filter(c => c.tier === t && c.mark); return { enforced: ms.filter(c => c.mark === 'E').length, measured: ms.length, pct: ms.length ? 100 * ms.filter(c => c.mark === 'E').length / ms.length : null } }
      const leads = (LEADS[g] || []).map(re => inG.find(c => re.test(c.label))).filter(c => c && ratio(c))
      const fallback = inG.filter(c => ratio(c) && !leads.includes(c)).slice(0, 2 - leads.length)
      return { group: g, foundational: tierCount('foundational'), defense: tierCount('defense'), measure: [...leads, ...fallback].slice(0, 2).map(c => `${ofText(c)} ${UNIT[short(c)] || short(c)}`).join(' · '), ungathered: inG.filter(ungathered).length }
    })

    // The register: every control, with a value that is never null.
    s.register = GROUPS.map(g => {
      const inG = m.controls.filter(c => c.group === g)
      const rows = t => inG.filter(c => c.tier === t).map(c => ({ ...safe(c), chip: c.mark || (c.na ? 'N/A' : '–') }))
      const counts = ['E', 'P', 'N'].map(k => [k, inG.filter(c => c.mark === k).length]).filter(([, n]) => n).map(([k, n]) => `${n} ${k}`)
      const dash = inG.filter(ungathered).length, na = inG.filter(c => c.na).length
      return { group: g, foundational: rows('foundational'), defense: rows('defense'), summary: [...counts, ...(dash ? [`${dash} –`] : []), ...(na ? [`${na} N/A`] : [])].join(' · ') }
    })

    // Takeaway subtitles, one sentence built from each slide's lead metric.
    const threatLine = m.alerts && m.alerts.flaggedKnown && m.alerts.truePositives > 0 && m.alerts.flagged === 0 ? (m.alerts.truePositives === 1 ? 'The confirmed threat did not reach exfiltration or impact' : `${m.alerts.truePositives === 2 ? 'Neither' : 'None of the'} confirmed ${m.alerts.truePositives === 2 ? 'threat' : 'threats'} reached exfiltration or impact`) : null
    const parts = [threatLine, gain ? `secure score rose ${fmt(gain.points)} points` : null, !threatLine && s.foundational.measured && s.foundational.enforced === s.foundational.measured ? 'every measured foundational control is enforced' : null].filter(Boolean)
    s.takeaways = {
      summary: parts.length ? `${sentence(parts.join(', and '))}.` : m.alerts ? `${fmt(m.alerts.triaged)} alerts triaged ${s.periodPhrase}.` : 'Readings are completed in the review.',
      wins: `${sentence(word(s.wins.length))} ${s.wins.length === 1 ? 'outcome' : 'outcomes'} ${m.period.valid ? `from ${m.period.label}` : ''}, one from each part of the service, each traced to collected evidence.`.replace(/\s+,/, ','),
      operations: m.alerts ? `${fmt(m.alerts.triaged)} alerts triaged ${s.periodPhrase}.${s.speed ? ` ${s.speed.line}` : ''}` : 'Alert readings are completed in the review.',
      threats: m.threats ? `${m.alerts && m.alerts.truePositives ? `${sentence(plural(m.alerts.truePositives, 'confirmed threat was', 'confirmed threats were'))} investigated and closed.` : 'Confirmed threats were investigated and closed.'}${threatLine ? ` ${sentence(threatLine)}.` : ''}` : '',
      posture: s.foundational.measured ? `${fmt(s.foundational.enforced)} of ${fmt(s.foundational.measured)} foundational controls are enforced.${s.drift.length ? ` ${sentence(word(s.drift.length))} ${s.drift.length === 1 ? 'has' : 'have'} drifted and ${s.drift.length === 1 ? 'is' : 'are'} first on the roadmap.` : ' None has drifted.'}` : 'Control readings are completed in the review.',
      roadmap: 'Every control below enforced is sequenced into three horizons by risk and by what each needs from your team.',
      passwordless: pw ? `Microsoft retires text message and voice sign-in on ${RETIREMENT.label}. ${plural(pw.retiring, 'user still relies', 'users still rely')} on it.` : '',
      decisions: s.asks.length ? `${sentence(word(s.asks.length))} ${s.asks.length === 1 ? 'item needs' : 'items need'} approval or access from your team to keep the roadmap on schedule.` : 'No approvals or access are needed before the next review.'
    }
    return s
  }

  const api = { buildStory, CATALOG, HORIZONS }
  if (typeof module !== 'undefined' && module.exports) module.exports = api
  else root.EbrStory = api
})(typeof globalThis !== 'undefined' ? globalThis : this)
