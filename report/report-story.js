/* The story behind the EBR deck, derived from the report model: outcome KPIs, wins, the watch list,
   the items that need action, foundational gaps, the posture matrix, the Now, Next and Later roadmap and
   the takeaway subtitles. Pure, so the HTML can adopt it later. Rules are in
   docs/plans/2026-10-12-ebr-deck-restructure-design.md.

   Copy rules hold here too: alerts not incidents, no semicolons or arrows, open alert counts and
   severity increases never appear (they stay in the presenter notes), medians under the 20 minute
   floor are never shown, and containment is never claimed. A foundational control below E is a gap
   against the baseline, never drift or a regression: the evidence shows the current reading only
   (Oct 14, 2026). */
(function (root) {
  'use strict'
  const R = typeof module !== 'undefined' && module.exports ? require('./report-model.js') : root.EbrReport
  const { fmt, clean, pctText, plural, E_THRESHOLD, RETIREMENT, MIN_SAMPLE, smallSampleText } = R
  const WORDS = ['no', 'one', 'two', 'three', 'four', 'five', 'six', 'seven', 'eight', 'nine', 'ten']
  const word = n => n >= 0 && n < WORDS.length ? WORDS[n] : fmt(n)
  const GROUPS = ['Identity and access', 'Endpoint and workload', 'Network and boundary', 'Data protection', 'Detection and response']
  const isoDay = v => String(v ?? '').slice(0, 10)
  const days = (from, to) => /^\d{4}-\d{2}-\d{2}$/.test(isoDay(from)) && /^\d{4}-\d{2}-\d{2}$/.test(isoDay(to)) ? Math.round((Date.parse(isoDay(to)) - Date.parse(isoDay(from))) / 864e5) : null
  const shortDate = v => /^\d{4}-\d{2}-\d{2}$/.test(isoDay(v)) ? new Date(isoDay(v) + 'T12:00:00Z').toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric', timeZone: 'UTC' }) : ''
  const list = items => items.length <= 1 ? items.join('') : `${items.slice(0, -1).join(', ')} and ${items[items.length - 1]}`
  const sentence = text => { const t = clean(text); return t ? t.charAt(0).toUpperCase() + t.slice(1) : '' }
  // A ratio control on a small sample (the model's smallSample, fewer than MIN_SAMPLE resources or more machines
  // excluded by tag than assessed) never leads a pillar or stands as a win: "2 of 2" is accurate but carries no
  // weight beside the figures around it (Oct 14, 2026). It keeps its mark in the tier counts, and every count that
  // holds one names it beside the total (Oct 18, 2026, issue #24).
  const small = n => n ? ` (${smallSampleText(n)})` : ''

  // Short names for the controls, used in grouped roadmap items, the drift panel and the asks.
  const SHORT = [
    [/^Multifactor authentication required at sign-in/, 'MFA at sign-in'], [/^Location-based sign-in/, 'location-based sign-in controls'],
    [/^Legacy authentication/, 'legacy authentication blocking'], [/^Anti-phishing policy applied/, 'anti-phishing policy'],
    [/^Multifactor authentication at admin portal/, 'admin portal MFA'], [/^Device code flow/, 'device code blocking'],
    [/^Advanced anti-phishing/, 'advanced anti-phishing'], [/^Privileged roles/, 'PIM eligibility'], [/^Identity Protection/, 'user and sign-in risk policies'],
    [/^Application consent/, 'app consent workflow'], [/^Azure virtual machines reporting/, 'Azure VM endpoint detection'],
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
    [/^Domain controller telemetry/, 'domain controller telemetry'], [/^Alerts closed with a documented/, 'documented dispositions'], [/^Defender for Identity sensors/, 'Defender for Identity'],
    [/^Audit logging initiative/, 'audit logging initiative'], [/^Analytics rules/, 'analytics rules'], [/^Threat intelligence/, 'threat intelligence'], [/^Diagnostic logging/, 'diagnostic logging']
  ]
  const short = c => (SHORT.find(([re]) => re.test(c.label)) || [null, c.label.charAt(0).toLowerCase() + c.label.slice(1)])[1]

  // Roadmap catalog for defense in depth controls (foundational controls below E are drift and go to Now).
  // Horizons follow the "why it waits" column of the controls baseline: Next needs configuration or an
  // approval, Later needs a maintenance window, a design change or licensing. Every below-E defense in depth
  // control must match an item here (tests/ebr-report-story.test.cjs enforces it). Analytics rules and threat
  // intelligence are foundational since Oct 16, 2026, so they left the detect item, which became vulnassess.
  const CATALOG = [
    { key: 'idp', horizon: 'next', title: 'Identity Protection user risk', match: /^Identity Protection/, ask: { title: 'Approve the user-risk policy', body: 'Sign-in and user risk policies for all users, with leaked credential response.' } },
    { key: 'phish', horizon: 'next', title: 'Advanced anti-phishing', match: /^Advanced anti-phishing/ },
    { key: 'consent', horizon: 'next', title: 'Application consent governance', match: /^Application consent/, ask: { title: 'Approve the admin consent workflow', body: 'Users request app consent and an administrator approves it.' } },
    { key: 'workload', horizon: 'next', title: 'Workload protection scope', match: /^Cloud workload protection/, priority: 'DR.2' },
    { key: 'logging', horizon: 'next', title: 'Diagnostic logging', match: /^(Diagnostic logging|Audit logging initiative)/, priority: 'DR.13' },
    { key: 'kvrbac', horizon: 'next', title: 'Key Vault access model', match: /^Key Vault access governed/ },
    { key: 'diskenc', horizon: 'next', title: 'Endpoint disk encryption', match: /^Endpoint disk encryption/ },
    { key: 'containers', horizon: 'next', title: 'Public blob containers', match: /^Blob containers closed/, ask: { title: 'Confirm which public containers are intended', body: 'Containers set to public access are made private unless they serve public content by design.' } },
    { key: 'vulnassess', horizon: 'next', title: 'Vulnerability assessment coverage', match: /^Vulnerability assessment/ },
    { key: 'segment', horizon: 'later', title: 'Network segmentation and exposure', match: /^(Workload subnets|Storage accounts closed to public)/, priority: 'NB.1', ask: { title: 'Agree a segmentation design and change windows', body: 'Network security groups or firewall routes on every workload subnet, and private access for storage.' } },
    { key: 'windows', horizon: 'later', title: 'Windows protocol hardening', match: /^(Remote Desktop|NTLMv2|Directory traffic|Credential protection)/ },
    // The backup coverage validation is not a catalog item: it is built in Now beside the extension (issue #25).
    { key: 'backup', horizon: 'later', title: 'Azure Backup extension', match: /^Azure Backup/, priority: 'DP.5b', ask: { title: 'Agree which machines persist and approve backup cost', body: 'Azure Backup on every persistent virtual machine, with pooled session hosts excluded by agreement.' } },
    { key: 'vmplatform', horizon: 'later', title: 'Encryption at host and Trusted Launch', match: /^(Encryption at host|Platform integrity)/ },
    { key: 'pim', horizon: 'later', title: 'Privileged role eligibility', match: /^Privileged roles/ },
    { key: 'allowlist', horizon: 'later', title: 'Application allow-listing', match: /^Application allow-listing/ },
    { key: 'sharing', horizon: 'later', title: 'Collaboration sharing boundaries', match: /^Collaboration sharing/ },
    // Defense in depth since Oct 16, 2026: it needs a license and a sensor on each domain controller from the client.
    // Domain controller telemetry comes from the same sensors, so its gap joins this item. The licensing ask is raised
    // only by the sensor control (askOn): with sensors healthy, a telemetry gap is an ingestion fault, not licensing.
    { key: 'mdi', horizon: 'later', title: 'Defender for Identity deployment', match: /^(Defender for Identity sensors|Domain controller telemetry)/, askOn: /^Defender for Identity sensors/, ask: { title: 'Approve Defender for Identity licensing', body: 'Licensing and a sensor on each domain controller, so identity attacks on the directory are detected.' } }
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
    const weighty = c => ratio(c) && !c.smallSample
    const find = re => m.controls.find(c => re.test(c.label))
    const ofText = c => `${fmt(c.good)} of ${fmt(c.total)}`
    const valueText = c => c.na ? 'N/A' : ungathered(c) ? 'Not gathered' : c.boolean ? c.value : c.total > 9999 ? pctText(c.pct) : c.value
    // The figure beside a control on the gap panel and the roadmap: the ratio behind a Mostly enforced policy, or
    // what a partially covered control is missing, such as the resource types outside workload protection.
    const detailText = c => [c.ratioText, c.gap].filter(Boolean).join(' · ')
    // Copies of controls carry valueText in place of the model's value, so no story field reads (null).
    const safe = c => ({ ...c, value: valueText(c), valueText: valueText(c), detail: detailText(c), short: short(c) })
    const s = { groups: GROUPS, horizons: HORIZONS }

    // Period. A calendar quarter gets a label, and "this quarter" in the takeaways.
    const start = isoDay(m.period.start), end = isoDay(m.period.end)
    const qStart = /^\d{4}-(01|04|07|10)-01$/.test(start), q = qStart ? (Number(start.slice(5, 7)) + 2) / 3 : null
    const qEnd = q ? `${start.slice(0, 4)}-${String(q * 3).padStart(2, '0')}` : null
    s.quarter = q && m.period.months === 3 && end.startsWith(qEnd) ? `Q${q} ${start.slice(0, 4)}` : null
    s.periodPhrase = s.quarter ? 'this quarter' : m.period.valid ? `from ${m.period.label}` : 'in the period'
    s.readShort = shortDate(p.PostureReadDate) || m.readDate

    // Response speed from the model's fixed cohort, every high severity alert created in the period and closed by
    // collection, so the KPI never
    // switches cohort or measure with the result. A median under 20 minutes or a 90th percentile over one hour keeps
    // its note. The 90th percentile is creation to recorded close, so it reads as nine in ten alerts triaged and
    // closed, as the HTML tile words it, never as investigated or resolved (Oct 16, 2026).
    const r = m.response
    s.speed = null
    if (r) {
      const nineInTen = r.p90 ? `Nine in ten triaged and closed within ${r.p90.value}` : ''
      s.speed = { value: r.median.value, label: 'median time to close, high severity alerts', sub: [`${plural(r.n, 'alert', 'alerts')} closed.`, nineInTen ? `${nineInTen}.` : '', ...r.notes].filter(Boolean).join(' '), kpiSub: [nineInTen || `${plural(r.n, 'alert', 'alerts')} closed`, ...r.notes.map(t => t.replace(/\.$/, ''))].join('. '), line: [`High-severity alerts closed in a median of ${r.median.value}.`, ...r.notes].join(' '), row: { source: r.median.source } }
    }

    // Score movement. Only a gain is a headline. The posture chart shows the monthly trend in either direction.
    const score = m.tenantScore || m.cloudScore
    const scoreName = m.tenantScore ? 'Microsoft Secure Score' : 'Defender for Cloud secure score'
    const gain = score && score.delta && score.delta.points > 0 ? score.delta : null

    // Drift and controls.
    const measured = tier => m.controls.filter(c => c.tier === tier && c.mark)
    const enforced = tier => measured(tier).filter(c => c.mark === 'E')
    // Foundational gaps: every foundational control below E. Defender for Identity, which needs a license and
    // sensors from the client, is defense in depth since Oct 16, 2026 and goes to Later through the catalog.
    // One MFA gap: the admin portal policy is part of the same Conditional Access work as MFA at sign-in, so
    // when both read below E the gaps panel, the roadmap and the summary name the sign-in gap once, with the admin portal reading folded into its figure line. The
    // counts still cover every control, and the register in the appendix keeps both rows (Oct 14, 2026).
    s.driftControls = m.controls.filter(c => c.tier === 'foundational' && below(c)).map(safe)
    const mfaGap = s.driftControls.find(c => /^Multifactor authentication required at sign-in/.test(c.label))
    const portalGap = s.driftControls.find(c => /^Multifactor authentication at admin portal/.test(c.label))
    if (mfaGap && portalGap) {
      mfaGap.folded = [portalGap]
      mfaGap.detail = [mfaGap.detail, `admin portals ${(portalGap.detail || portalGap.valueText).toLowerCase()}`].filter(Boolean).join(' · ')
    }
    s.drift = s.driftControls.filter(c => c !== portalGap || !mfaGap)
    s.ungathered = m.controls.filter(ungathered).map(safe)
    const tierTotal = tier => ({ enforced: enforced(tier).length, measured: measured(tier).length, small: measured(tier).filter(c => c.smallSample).length })
    s.foundational = tierTotal('foundational')
    s.defense = tierTotal('defense')

    // Outcome KPIs: alerts, impact, speed, score. Scope figures such as resources assessed are inputs, not outcomes.
    // The alert KPI carries the period, or the automation line, as the HTML tile does. The detection count stays
    // on the operations slide, where the chart explains it.
    const kpis = []
    if (m.alerts) kpis.push({ value: fmt(m.alerts.triaged), label: 'Alerts triaged', sub: m.alerts.analystMode ? `Plus ${fmt(m.alerts.automation)} closed by automation rules` : m.period.label, area: 'alerts' })
    // Tactic-qualified: the count is of tactics recorded on the alert (the model names the scope and the phrase),
    // never a verified outcome, so the label says carried, never reached. A true positive is a classification the
    // SOC recorded, so the sub-line says classified, never investigated or closed. A confirmed impact from the
    // reviewed context record (m.impact) withdraws the win and the tactic line, and the takeaways carry the
    // reviewed determination instead (Oct 15, 2026).
    const a = m.alerts
    const tpWord = n => n === 1 ? 'confirmed threat' : 'confirmed threats'
    const classified = n => n === 1 ? 'Classified as a true positive by the SOC' : `${n === 2 ? 'Both' : 'All'} classified as true positives by the SOC`
    const impactConfirmed = !!(m.impact && m.impact.confirmed > 0)
    if (a && a.flaggedKnown && a.truePositives > 0) kpis.push({ value: `${fmt(a.flagged)} of ${fmt(a.truePositives)}`, label: `True positives whose alerts carried ${a.tacticPhrase}`, sub: classified(a.truePositives), area: 'threat' })
    else if (a && a.truePositives !== null) kpis.push({ value: fmt(a.truePositives), label: 'Confirmed threats', sub: 'Alerts the SOC classified as true positives', area: 'threat' })
    if (s.speed) kpis.push({ value: s.speed.value, label: sentence(s.speed.label), sub: s.speed.kpiSub, area: 'response' })
    if (score) kpis.push({ value: pctText(score.value), label: scoreName, sub: gain ? `Up ${fmt(gain.points)} points since ${gain.since}, from ${pctText(gain.from)}` : `Read ${s.readShort}`, area: 'posture' })
    if (kpis.length < 4 && s.foundational.measured) kpis.push({ value: `${fmt(s.foundational.enforced)} of ${fmt(s.foundational.measured)}`, label: 'Foundational controls enforced', sub: `Across five pillars${s.foundational.small ? `, ${smallSampleText(s.foundational.small)}` : ''}`, area: 'controls' })
    s.kpis = kpis.slice(0, 4)

    // Wins, at most one per area, up to six. A verified configuration reads In force with its own label. A sub-line
    // may depend on the reading, so a win at E that leaves resources out never says none or every (Oct 15, 2026).
    const winAt = (re, area, label, sub, boolLabel = label, boolSub = sub) => { const c = find(re); return c && c.mark === 'E' && c.pct !== null && (c.boolean || !c.smallSample) ? { area, value: c.boolean ? c.value : ofText(c), label: c.boolean ? boolLabel : label, sub: c.boolean ? boolSub : (c.population || (typeof sub === 'function' ? sub(c) : sub)), source: c.source } : null }
    const candidates = [
      a && a.flaggedKnown && a.truePositives > 0 && a.flagged === 0 && !impactConfirmed ? { area: 'threat', eyebrow: 'Confirmed threats', value: `0 of ${fmt(a.truePositives)}`, label: `${tpWord(a.truePositives)} carried ${a.tacticPhrase}`, sub: `${classified(a.truePositives)} ${s.periodPhrase}.`, source: a.source } : null,
      s.speed ? { area: 'response', eyebrow: 'Response speed', value: s.speed.value, label: s.speed.label, sub: s.speed.sub, source: s.speed.row.source } : null,
      gain ? { area: 'posture', eyebrow: 'Posture', value: `+${fmt(gain.points)} pts`, label: `${scoreName}, ${pctText(gain.from)} in ${gain.since} to ${pctText(score.value)}`, sub: `Calculated by Microsoft, read ${score.read || s.readShort}.`, source: score.source } : null,
      winAt(/^Multifactor authentication required at sign-in/, 'identity', 'users challenged for MFA at sign-in', 'Members who signed in over the last 30 days.', 'multifactor authentication required at sign-in by Conditional Access policy', 'An enabled policy for all users on every application.'),
      winAt(/^Operating system findings/, 'endpoint', 'machines patched inside the agreed cadence', c => c.good === c.total ? 'No critical or security patch past the cadence at collection.' : `${plural(c.total - c.good, 'machine carries', 'machines carry')} a critical or security patch past the cadence at collection.`) || winAt(/^Azure virtual machines reporting/, 'endpoint', 'Azure virtual machines reporting to endpoint detection', 'Seen in the last 7 days.'),
      m.mailRemoved > 0 && find(/^Malicious mail removed/)?.mark === 'E' ? { area: 'data', eyebrow: 'Email protection', value: fmt(m.mailRemoved), label: 'malicious messages removed after delivery', sub: 'Zero-hour auto purge and automated remediation, last 30 days.', source: find(/^Malicious mail removed/).source } : winAt(/^Managed disks/, 'data', 'managed disks encrypted at rest', 'Platform or customer managed keys, at collection.'),
      // The DR.10 win reads the last 30 days beside quarterly figures, so its label names the window and its sub-line
      // names the unclassified closures from OUT.1 when there are any: alerts created in the period and closed by collection,
      // since OUT.1 reads the latest state at collection (Oct 16, 2026).
      winAt(/^Alerts closed with a documented/, 'detection', 'alerts closed in the last 30 days with a documented disposition', a && a.unclassified > 0 ? `Classification and closing comment. ${plural(a.unclassified, 'alert', 'alerts')} created ${s.periodPhrase} and closed by collection ${a.unclassified === 1 ? 'carries' : 'carry'} no classification.` : 'Classification and closing comment.'),
      winAt(/^Encryption in transit/, 'network', 'published web apps enforcing HTTPS only', 'At collection.')
    ].filter(Boolean)
    const EYEBROW = { identity: 'Identity', endpoint: 'Endpoint', data: 'Data protection', detection: 'Detection', network: 'Network' }
    s.wins = candidates.slice(0, 6).map(w => ({ ...w, eyebrow: w.eyebrow || (w.label.startsWith('machines patched') ? 'Patching' : EYEBROW[w.area]) }))

    // Reviewed action status. A roadmap item or an ask reads scheduled, approved, in progress or verified only from an
    // Actions record in the context file with its key (the model validates the record, Oct 16, 2026). Without one the
    // copy reads as a recommendation, and the drift panel and the vulnerability item say what Atmosera recommends.
    const actionOf = key => (m.actions || []).find(x => x.key === key) || null
    const statusLead = x => `${x.label}${x.owner ? `, owner ${x.owner}` : ''}${x.targetDate ? `, target ${x.targetDate}` : ''}`
    const statusText = x => `${statusLead(x)} (${x.reference}, reviewed ${x.reviewed})`
    const withStatus = (text, x) => !x ? text : !clean(text) ? statusText(x) : `${clean(text).replace(/\.$/, '')}. ${statusText(x)}${/\.$/.test(clean(text)) ? '.' : ''}`
    const driftAction = actionOf('drift')
    s.driftAction = driftAction
    s.driftNote = `Below the baseline at collection. ${driftAction ? `Fixes ${driftAction.label.toLowerCase()} (${driftAction.reference}).` : 'Atmosera recommends closing each gap first.'}`

    // The roadmap: every below-E control mapped to a catalog item, drift first in Now.
    const items = { now: [], next: [], later: [] }
    const prio = id => m.priorities.find(x => x.id === id)
    if (s.drift.length) items.now.push({ key: 'drift', title: 'Close foundational gaps', evidence: `${plural(s.driftControls.length, 'control', 'controls')} below the baseline: ${list(s.drift.map(c => c.detail ? `${c.short} (${c.detail})` : c.short))}`, controls: s.driftControls, owner: 'Atmosera' })
    const crit = prio('BKL.1')
    if (m.criticalCves > 0) items.now.push({ key: 'critical', title: 'Critical vulnerability remediation', evidence: `${plural(m.criticalCves, 'critical exploitable finding', 'critical exploitable findings')}.${actionOf('critical') ? '' : ' Atmosera recommends validating the affected workloads and agreeing remediation or compensating controls with the owners inside the patch cadence.'}`, controls: [], priority: crit })
    // The MFA method update: users still on text message or voice move to a stronger method before Microsoft
    // retires those methods. Never framed as a passwordless programme (Oct 14, 2026).
    const pw = m.mfaMethods && m.mfaMethods.retiring > 0 ? m.mfaMethods : null
    s.deadlineDays = days(p.PostureReadDate, RETIREMENT.date)
    s.deadlineShort = shortDate(RETIREMENT.date)
    if (pw) items[s.deadlineDays !== null && s.deadlineDays <= 180 ? 'now' : 'next'].push({ key: 'methods', title: 'MFA method update', evidence: `${plural(pw.retiring, 'user', 'users')} on text message or voice, ahead of ${RETIREMENT.shortText}`, controls: [], priority: prio('IA.2') })
    // Backup coverage validation: when fewer than half of a weighty virtual machine estate carries a protected Azure
    // Backup item, confirming which machines persist is no-cost shared work, so it starts in Now. The extension stays in
    // Later under the backup key with its ask, and from half to 89 percent, or on a small sample, it is the only item. The
    // raw counts decide, since pct is rounded (500 of 1,001 reads 50.0). The validation keeps to what DP.5b measures and
    // reads as a recommendation (Oct 18, 2026, issue #25).
    const backup = m.controls.find(c => c.id === 'DP.5b' && ratio(c))
    if (backup && backup.good * 2 < backup.total && !backup.smallSample) items.now.push({ key: 'backupcheck', title: 'Backup coverage validation', evidence: `${ofText(backup)} virtual machines ${backup.good === 1 ? 'carries' : 'carry'} a protected Azure Backup item.${actionOf('backupcheck') ? '' : ' Atmosera recommends confirming with your team which machines without one persist, to separate confirmed gaps from agreed exclusions.'}`, controls: [], owner: 'Atmosera and client', priority: prio('DP.5b') })
    const mapped = new Set(s.driftControls.map(c => c.label))
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
      if (entry && !items[entry.horizon].some(i => i.key === entry.key) && !s.driftControls.some(c => entry.match.test(c.label))) items[entry.horizon].push({ key: entry.key, title: entry.title, controls: [], priority: pr })
    }
    if (other.length) items.next.push({ key: 'other', title: 'Other controls', controls: other.map(safe) })
    const evidenceOf = item => item.evidence || (item.controls.length === 1 && item.priority ? item.priority.evidence
      : item.controls.length === 1 && item.controls[0].boolean && item.controls[0].note ? item.controls[0].note
      : item.controls.length ? item.controls.map(c => `${sentence(c.short)} ${c.valueText}${c.detail ? `, ${c.detail}` : ''}`).join(' · ') : item.priority ? item.priority.evidence : '')
    s.roadmap = HORIZONS.map(h => ({ ...h, items: items[h.key].map(i => { const action = i.key === 'other' ? null : actionOf(i.key); return { ...i, action, evidence: clean(withStatus(evidenceOf(i), action)) } }) }))
    s.unmapped = other.map(c => c.label)
    const headroom = m.posture && m.posture.scoreControls ? m.posture.scoreControls.filter(c => /vulnerabilit|security configuration/i.test(c.label)) : []
    const available = m.cloudScore ? Number((m.cloudScore.max - m.cloudScore.current).toFixed(2)) : null
    s.headroom = headroom.length && available ? `Vulnerability and configuration remediation hold ${fmt(Number(headroom.reduce((n, c) => n + c.remaining, 0).toFixed(2)))} of the ${fmt(available)} secure score points still available.` : ''

    // Decisions needed: the MFA method update, read access, then approvals for items whose controls read N.
    // Each ask carries a kind, so the executive summary can leave the read access ask to the closing slide.
    // An approval ask, or the MFA method update, whose reviewed record reads approved, scheduled, in progress or
    // verified is no longer a decision, so it leaves the list before the four-ask limit and the count, and its roadmap
    // item carries the status instead. The speaker notes name it. The read access ask is different: no status
    // establishes that the permission was provisioned, so it stays, with its status, until a collection reads the
    // evidence (Oct 16, 2026).
    const SETTLED = ['Approved', 'Scheduled', 'InProgress', 'Verified']
    const settled = []
    const asks = []
    const open = (key, title) => { const x = actionOf(key); if (x && SETTLED.includes(x.status)) { if (!settled.some(t => t.key === key)) settled.push({ key, title, status: statusText(x) }); return false } return true }
    if (pw && open('methods', 'Move users off text message and voice MFA')) asks.push({ kind: 'methods', key: 'methods', lead: plural(pw.retiring, 'user', 'users'), title: 'Move users off text message and voice MFA', body: `${plural(pw.retiring, 'user', 'users')} on text message or voice, which retire ${RETIREMENT.shortText}.`, short: `on text message or voice MFA ahead of ${RETIREMENT.shortText}` })
    // Read access is asked for only where the collector was not permitted to read the evidence. Service
    // errors and packs that only need recollection are Atmosera's to resolve.
    const gap = id => (data.manifest || []).some(r => r.ResultId === id && (r.AccessGap === true || String(r.AccessGap).toLowerCase() === 'true'))
    const unread = s.ungathered.filter(c => gap(c.id))
    if (unread.length) asks.push({ kind: 'access', key: 'access', lead: plural(unread.length, 'control', 'controls'), title: `Grant read access for ${unread.length === 1 ? 'one ungraded control' : `${word(unread.length)} ungraded controls`}`, body: `${sentence(list(unread.map(short)))}.`, short: 'Grant the read access needed to grade them' })
    for (const item of HORIZONS.flatMap(h => items[h.key])) {
      const entry = CATALOG.find(e => e.key === item.key)
      if (asks.length < 4 && entry && entry.ask && item.controls.some(c => c.mark === 'N' && (!entry.askOn || entry.askOn.test(c.label))) && open(entry.key, entry.ask.title)) asks.push({ kind: 'approval', key: entry.key, lead: plural(item.controls.length, 'control', 'controls'), title: entry.ask.title, body: entry.ask.body, short: entry.ask.title })
    }
    // The deck sizes the card text from bodyText and the action, and keeps the full body with its attribution in the notes.
    s.asks = asks.slice(0, 4).map(x => { const action = actionOf(x.key); return { ...x, action, bodyText: x.body, body: clean(withStatus(x.body, action)) } })
    s.settledAsks = settled

    // Executive summary columns. Wins and watch items avoid numbers already in the KPI strip.
    const kpiAreas = new Set(s.kpis.map(k => k.area))
    s.summaryWins = [
      s.foundational.measured && !kpiAreas.has('controls') ? { value: `${fmt(s.foundational.enforced)} of ${fmt(s.foundational.measured)}`, label: `foundational controls enforced across five pillars${small(s.foundational.small)}` } : null,
      ...s.wins.filter(w => !kpiAreas.has(w.area)).map(w => ({ value: w.value, label: w.label + (/last 30 days/.test(w.sub) ? ', last 30 days' : '') }))
    ].filter(Boolean).slice(0, 3)
    const watch = []
    if (m.criticalCves > 0) watch.push({ value: fmt(m.criticalCves), label: m.criticalCves === 1 ? 'critical exploitable vulnerability open' : 'critical exploitable vulnerabilities open' })
    const belowCount = s.driftControls.length
    if (belowCount) watch.push({ value: fmt(belowCount), label: belowCount === 1 ? 'foundational control reads below enforced' : 'foundational controls read below enforced' })
    const singular = label => [['Members who', 'Member who'], ['Members', 'Member'], ['Users', 'User'], ['Devices', 'Device'], ['AI service resources', 'AI service resource'], ['Resources', 'Resource'], ['Virtual machines', 'Virtual machine'], ['Workload subnets', 'Workload subnet'], ['Key Vaults', 'Key Vault'], ['Storage accounts', 'Storage account'], ['Critical exploitable findings', 'Critical exploitable finding']].reduce((l, [many, one]) => l.startsWith(many + ' ') ? one + l.slice(many.length) : l, label)
    for (const h of (m.hardening || []).filter(x => x.rank < 99 && !['BKL.1', 'IA.2'].includes(x.id))) {
      const label = h.value === 1 ? singular(h.label) : h.label
      if (watch.length < 3) watch.push({ value: h.of ? `${fmt(h.value)} of ${fmt(h.of)}` : fmt(h.value), label: label.charAt(0).toLowerCase() + label.slice(1) })
    }
    s.watch = watch.slice(0, 3)
    // Items that need action from the client. Read access is Atmosera's to arrange and stays on the closing slide.
    s.summaryAsks = s.asks.filter(a => a.kind !== 'access').slice(0, 3).map(a => ({ value: a.lead, label: a.short }))

    // Posture matrix: per pillar, foundational and defense in depth counts and a headline measure.
    const LEADS = { 'Identity and access': [/^Multifactor authentication required at sign-in/, /^Multifactor authentication at admin portal/], 'Endpoint and workload': [/^Azure virtual machines reporting/, /^Operating system findings/], 'Network and boundary': [/^Encryption in transit/, /^Workload subnets/], 'Data protection': [/^Managed disks/, /^Secure transfer/], 'Detection and response': [/^Alerts closed with a documented/, /^Analytics rules/] }
    const UNIT = { 'MFA at sign-in': 'users on MFA at sign-in', 'admin portal MFA': 'admins on MFA', 'Azure VM endpoint detection': 'Azure VMs on endpoint detection', 'patch cadence': 'patched in cadence', 'HTTPS-only web apps': 'web apps HTTPS-only', 'subnet segmentation': 'subnets segmented', 'disk encryption at rest': 'disks encrypted at rest', 'storage secure transfer': 'with secure transfer', 'documented dispositions': 'closures documented', 'analytics rules': 'rules enabled',
      'real-time anti-malware': 'VMs with real-time anti-malware', 'vulnerability assessment': 'VMs under vulnerability assessment', 'tamper protection': 'VMs with tamper protection', 'host firewall': 'VMs with host firewall', 'endpoint sensors': 'sensors active', 'Azure SQL TLS': 'SQL servers on TLS 1.2', 'App Service TLS 1.2': 'App Service configs on TLS 1.2', 'storage TLS 1.2': 'storage accounts on TLS 1.2', 'Key Vault soft delete': 'vaults with soft delete', 'Key Vault purge protection': 'vaults with purge protection', 'workload protection': 'resources with workload protection', 'diagnostic logging': 'resources with diagnostic logging', 'public blob containers': 'containers private', 'anonymous blob access': 'accounts with anonymous access off' }
    s.matrix = GROUPS.map(g => {
      const inG = m.controls.filter(c => c.group === g)
      const tierCount = t => { const ms = inG.filter(c => c.tier === t && c.mark); return { enforced: ms.filter(c => c.mark === 'E').length, measured: ms.length, small: ms.filter(c => c.smallSample).length, pct: ms.length ? 100 * ms.filter(c => c.mark === 'E').length / ms.length : null } }
      const leads = (LEADS[g] || []).map(re => inG.find(c => re.test(c.label))).filter(c => c && weighty(c))
      const fallback = inG.filter(c => weighty(c) && !leads.includes(c)).slice(0, 2 - leads.length)
      let measure = [...leads, ...fallback].slice(0, 2).map(c => `${ofText(c)} ${UNIT[short(c)] || short(c)}`).join(' · ')
      // A pillar whose graded controls are all policy readings takes its measure from the pillar page: the sign-in
      // ratio behind the MFA policy and the callout, so the matrix never reads "completed in the review" beside real
      // figures. The minimum population applies there too, and a callout that repeats the measure is left out.
      const page = (m.pillars || []).find(p => p.name === g)
      if (!measure && page && !inG.some(ratio)) {
        const pageMeasure = page.measure && page.measure.total >= MIN_SAMPLE ? `${fmt(page.measure.good)} of ${fmt(page.measure.total)}` : ''
        const calloutSmall = page.callout && /^(\d[\d,]*) of (\d[\d,]*)$/.test(page.callout.value) && Number(page.callout.value.replace(/^.* of /, '').replace(/,/g, '')) < MIN_SAMPLE
        const callout = page.callout && !calloutSmall && page.callout.value !== pageMeasure ? `${page.callout.value} ${page.callout.label}` : ''
        measure = [pageMeasure ? `${pageMeasure} ${page.measure.label.charAt(0).toLowerCase() + page.measure.label.slice(1)}` : '', callout].filter(Boolean).join(' · ')
      }
      return { group: g, foundational: tierCount('foundational'), defense: tierCount('defense'), measure, ungathered: inG.filter(ungathered).length }
    })

    // The register: every control, with a value that is never null. A control at E that leaves resources out
    // carries its exception count, so E with exceptions never reads as E with none (Oct 15, 2026). A control on a
    // small sample carries the flag, and the patch cadence row names its assessed and excluded populations (issue #24).
    s.register = GROUPS.map(g => {
      const inG = m.controls.filter(c => c.group === g)
      // A control whose grade covers part of its population (MFA at sign-in in a federated tenant, or with MFA
      // inferred from the session) carries the split on its detail line.
      const rows = t => inG.filter(c => c.tier === t).map(c => ({ ...safe(c), detail: [detailText(c), c.split, c.populations].filter(Boolean).join(' · '), chip: c.mark || (c.na ? 'N/A' : '–'), exceptionText: c.exceptions > 0 ? plural(c.exceptions, 'exception', 'exceptions') : '', sampleText: c.mark && c.smallSample ? 'small sample' : '' }))
      const counts = ['E', 'P', 'N'].map(k => [k, inG.filter(c => c.mark === k).length]).filter(([, n]) => n).map(([k, n]) => `${n} ${k}`)
      const dash = inG.filter(ungathered).length, na = inG.filter(c => c.na).length
      return { group: g, foundational: rows('foundational'), defense: rows('defense'), summary: [...counts, ...(dash ? [`${dash} –`] : []), ...(na ? [`${na} N/A`] : [])].join(' · ') }
    })

    // Takeaway subtitles, one sentence built from each slide's lead metric.
    // The tactic line names a tactic recorded on the alert, never an outcome. The impact line exists only when the
    // context file carries a reviewed determination, and it leads the summary when it does.
    const threatLine = a && a.flaggedKnown && a.truePositives > 0 && a.flagged === 0 && !impactConfirmed ? (a.truePositives === 1 ? `The confirmed threat did not carry ${a.tacticPhrase}` : `${a.truePositives === 2 ? 'Neither confirmed threat' : 'None of the confirmed threats'} carried ${a.tacticPhrase}`) : null
    const impactLine = m.impact && a && a.truePositives > 0 ? (m.impact.confirmed === 0 ? 'the reviewed investigation records confirm no data exposure or business impact' : `the reviewed investigation records confirm data exposure or business impact from ${a.truePositives === 1 ? 'the confirmed threat' : `${fmt(m.impact.confirmed)} of the ${fmt(a.truePositives)} confirmed threats`}`) : null
    const lead = impactLine || threatLine
    const parts = [lead, gain ? `secure score rose ${fmt(gain.points)} points` : null, !lead && s.foundational.measured && s.foundational.enforced === s.foundational.measured ? 'every measured foundational control is enforced' : null].filter(Boolean)
    s.takeaways = {
      summary: parts.length ? `${sentence(parts.join(', and '))}.` : m.alerts ? `${fmt(m.alerts.triaged)} alerts triaged ${s.periodPhrase}.` : 'Readings are completed in the review.',
      wins: `${sentence(word(s.wins.length))} ${s.wins.length === 1 ? 'outcome' : 'outcomes'} ${m.period.valid ? `from ${m.period.label}` : ''}, one from each part of the service, each traced to collected evidence.`.replace(/\s+,/, ','),
      operations: m.alerts ? `${fmt(m.alerts.triaged)} alerts triaged ${s.periodPhrase}.${s.speed ? ` ${s.speed.line}` : ''}` : 'Alert readings are completed in the review.',
      // The threats slide is built whenever the pack has true positives, with or without an examples table, so
      // the takeaway needs no examples either.
      threats: (a && a.truePositives > 0) || m.threats ? `${a && a.truePositives ? `The SOC classified ${plural(a.truePositives, 'alert', 'alerts')} as ${a.truePositives === 1 ? 'a true positive' : 'true positives'} ${s.periodPhrase}.` : 'Alerts were classified as true positives by the SOC.'}${threatLine ? ` ${sentence(threatLine)}.` : ''}${impactLine ? ` ${sentence(impactLine)}.` : ''}` : '',
      posture: s.foundational.measured ? `${fmt(s.foundational.enforced)} of ${fmt(s.foundational.measured)} foundational controls are enforced${small(s.foundational.small)}.${belowCount ? ` ${sentence(word(belowCount))} ${belowCount === 1 ? 'reads' : 'read'} below the baseline and ${belowCount === 1 ? 'is' : 'are'} first on the roadmap.` : ' None reads below the baseline.'}` : 'Control readings are completed in the review.',
      roadmap: 'Every control below enforced is proposed in one of three horizons, by risk and by what each needs from your team.',
      methods: pw ? `Microsoft retires text message and voice sign-in on ${RETIREMENT.text}. ${plural(pw.retiring, 'user', 'users')} signed in with it in the last 30 days.` : '',
      decisions: s.asks.length ? `${sentence(word(s.asks.length))} ${s.asks.length === 1 ? 'item needs' : 'items need'} approval or access from your team to move the roadmap forward.` : 'No approvals or access are needed before the next review.',
      // The grounding slides added Oct 14, 2026: measured outcomes by pillar and the priority workstreams.
      pillars: (() => { const n = s.matrix.filter(r => r.foundational.measured && r.foundational.enforced === r.foundational.measured).length; return n ? `${sentence(word(n))} of five pillars ${n === 1 ? 'has' : 'have'} every measured foundational control enforced. Each statement is earned by the evidence collected ${s.readShort}.` : `Each statement is earned by the evidence collected ${s.readShort}. The pillars that read lower are sequenced on the roadmap.` })(),
      priorities: m.priorities.length ? `${sentence(word(m.priorities.length))} ${m.priorities.length === 1 ? 'workstream' : 'workstreams'} sequenced from the collected evidence, ${m.priorities.length > 3 ? 'the first three' : 'each'} with the action and the outcome we verify at the next review.` : ''
    }
    return s
  }

  const api = { buildStory, CATALOG, HORIZONS, shortName: short }
  if (typeof module !== 'undefined' && module.exports) module.exports = api
  else root.EbrStory = api
})(typeof globalThis !== 'undefined' ? globalThis : this)
