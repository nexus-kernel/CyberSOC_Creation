/* CyberSOC monthly report derivation: the report month, the 90-day trend, threat intelligence and vulnerability
   management. Pure, like report-model.js, and run after it: build(data, m) reads the embedded pack data and the EBR
   report model m. Shared by the offline HTML, the client edition, the deck and the regression tests.

   The EBR report rules hold here too. Sentinel incidents are alerts and SecurityAlert records are detections. Visible
   copy carries no semicolons, arrows or emoji. Missing, failed, unavailable and uncollected evidence never becomes a
   favorable zero: a Log Analytics table no workspace holds reads EMPTY in the manifest, so every threat
   intelligence measure checks TI.0 (or the NoTable flag) before it reads a zero. Alert figures follow the EBR gate
   (m.alertsAllowed) and timing needs 5 closed alerts. Month over month figures are shown side by side with a neutral
   change, never as an improvement or a decline. */
(function (root) {
  'use strict'
  const R = typeof module !== 'undefined' && module.exports ? require('./report-model.js') : root.EbrReport
  const { fmt, clean, date, span, num, count, pct, pctText, plural, duration, MEDIAN_FLOOR, TIMING_SAMPLE, STAGES, stageIndex, stageLabel, alertWords, validDate, iso, monthLabel, monthName, list, array, bool } = R

  // MITRE ATT&CK Enterprise technique names for the IDs Sentinel records. A sub-technique reads with its parent's
  // name and its own ID, and an ID not listed here reads as the ID alone.
  const TECHNIQUES = {
    T1001: 'Data Obfuscation', T1003: 'OS Credential Dumping', T1005: 'Data from Local System', T1007: 'System Service Discovery',
    T1012: 'Query Registry', T1016: 'System Network Configuration Discovery', T1018: 'Remote System Discovery', T1020: 'Automated Exfiltration',
    T1021: 'Remote Services', T1027: 'Obfuscated Files or Information', T1033: 'System Owner/User Discovery', T1036: 'Masquerading',
    T1037: 'Boot or Logon Initialization Scripts', T1039: 'Data from Network Shared Drive', T1040: 'Network Sniffing', T1041: 'Exfiltration Over C2 Channel',
    T1046: 'Network Service Discovery', T1047: 'Windows Management Instrumentation', T1048: 'Exfiltration Over Alternative Protocol',
    T1049: 'System Network Connections Discovery', T1053: 'Scheduled Task/Job', T1055: 'Process Injection', T1056: 'Input Capture',
    T1057: 'Process Discovery', T1059: 'Command and Scripting Interpreter', T1068: 'Exploitation for Privilege Escalation',
    T1069: 'Permission Groups Discovery', T1070: 'Indicator Removal', T1071: 'Application Layer Protocol', T1072: 'Software Deployment Tools',
    T1074: 'Data Staged', T1078: 'Valid Accounts', T1082: 'System Information Discovery', T1083: 'File and Directory Discovery',
    T1087: 'Account Discovery', T1090: 'Proxy', T1098: 'Account Manipulation', T1102: 'Web Service', T1105: 'Ingress Tool Transfer',
    T1106: 'Native API', T1110: 'Brute Force', T1112: 'Modify Registry', T1113: 'Screen Capture', T1114: 'Email Collection',
    T1115: 'Clipboard Data', T1119: 'Automated Collection', T1124: 'System Time Discovery', T1133: 'External Remote Services',
    T1134: 'Access Token Manipulation', T1135: 'Network Share Discovery', T1136: 'Create Account', T1137: 'Office Application Startup',
    T1140: 'Deobfuscate/Decode Files or Information', T1176: 'Browser Extensions', T1185: 'Browser Session Hijacking', T1189: 'Drive-by Compromise',
    T1190: 'Exploit Public-Facing Application', T1195: 'Supply Chain Compromise', T1197: 'BITS Jobs', T1199: 'Trusted Relationship',
    T1201: 'Password Policy Discovery', T1202: 'Indirect Command Execution', T1203: 'Exploitation for Client Execution', T1204: 'User Execution',
    T1210: 'Exploitation of Remote Services', T1211: 'Exploitation for Defense Evasion', T1212: 'Exploitation for Credential Access',
    T1213: 'Data from Information Repositories', T1218: 'System Binary Proxy Execution', T1219: 'Remote Access Software',
    T1482: 'Domain Trust Discovery', T1484: 'Domain or Tenant Policy Modification', T1485: 'Data Destruction', T1486: 'Data Encrypted for Impact',
    T1489: 'Service Stop', T1490: 'Inhibit System Recovery', T1496: 'Resource Hijacking', T1497: 'Virtualization/Sandbox Evasion',
    T1498: 'Network Denial of Service', T1499: 'Endpoint Denial of Service', T1505: 'Server Software Component', T1518: 'Software Discovery',
    T1526: 'Cloud Service Discovery', T1528: 'Steal Application Access Token', T1530: 'Data from Cloud Storage', T1531: 'Account Access Removal',
    T1534: 'Internal Spearphishing', T1537: 'Transfer Data to Cloud Account', T1538: 'Cloud Service Dashboard', T1539: 'Steal Web Session Cookie',
    T1543: 'Create or Modify System Process', T1546: 'Event Triggered Execution', T1547: 'Boot or Logon Autostart Execution',
    T1548: 'Abuse Elevation Control Mechanism', T1550: 'Use Alternate Authentication Material', T1552: 'Unsecured Credentials',
    T1553: 'Subvert Trust Controls', T1555: 'Credentials from Password Stores', T1556: 'Modify Authentication Process',
    T1557: 'Adversary-in-the-Middle', T1558: 'Steal or Forge Kerberos Tickets', T1559: 'Inter-Process Communication',
    T1560: 'Archive Collected Data', T1562: 'Impair Defenses', T1563: 'Remote Service Session Hijacking', T1564: 'Hide Artifacts',
    T1565: 'Data Manipulation', T1566: 'Phishing', T1567: 'Exfiltration Over Web Service', T1568: 'Dynamic Resolution', T1569: 'System Services',
    T1570: 'Lateral Tool Transfer', T1571: 'Non-Standard Port', T1572: 'Protocol Tunneling', T1573: 'Encrypted Channel',
    T1574: 'Hijack Execution Flow', T1578: 'Modify Cloud Compute Infrastructure', T1580: 'Cloud Infrastructure Discovery',
    T1583: 'Acquire Infrastructure', T1584: 'Compromise Infrastructure', T1586: 'Compromise Accounts', T1588: 'Obtain Capabilities',
    T1589: 'Gather Victim Identity Information', T1590: 'Gather Victim Network Information', T1595: 'Active Scanning',
    T1598: 'Phishing for Information', T1606: 'Forge Web Credentials', T1609: 'Container Administration Command', T1610: 'Deploy Container',
    T1611: 'Escape to Host', T1613: 'Container and Resource Discovery', T1614: 'System Location Discovery', T1615: 'Group Policy Discovery',
    T1619: 'Cloud Storage Object Discovery', T1620: 'Reflective Code Loading', T1621: 'Multi-Factor Authentication Request Generation',
    T1649: 'Steal or Forge Authentication Certificates', T1651: 'Cloud Administration Command', T1656: 'Impersonation', T1657: 'Financial Theft'
  }
  // Microsoft Entra ID Protection risk detection types (riskEventType), with the names the Entra portal uses. An
  // administrator's compromise confirmation (adminConfirmedUserCompromised) is not a detection, and the CyberSOC
  // report carries no compromise determination, so its rows are left out of every risk figure (Oct 19, 2026).
  const RISK_EXCLUDED = new Set(['adminconfirmedusercompromised'])
  const RISK_TYPES = {
    anomaloustoken: 'Anomalous token', anomaloususeractivity: 'Anomalous user activity',
    anonymizedipaddress: 'Anonymous IP address', attackerinthemiddle: 'Attacker in the middle', impossibletravel: 'Impossible travel',
    investigationsthreatintelligence: 'Microsoft Entra threat intelligence', leakedcredentials: 'Leaked credentials', maliciousipaddress: 'Malicious IP address',
    mcasimpossibletravel: 'Impossible travel', mcassuspiciousinboxmanipulationrules: 'Suspicious inbox manipulation rules', newcountry: 'New country',
    passwordspray: 'Password spray', suspiciousapitraffic: 'Suspicious API traffic', suspiciousbrowser: 'Suspicious browser',
    suspiciousinboxforwarding: 'Suspicious inbox forwarding', suspicioussendingpatterns: 'Suspicious sending patterns', tokenissueranomaly: 'Token issuer anomaly',
    unfamiliarfeatures: 'Unfamiliar sign-in properties', unlikelytravel: 'Atypical travel', userreportedsuspiciousactivity: 'User reported suspicious activity'
  }
  // Atmosera.VulnAssessment remediation statuses, with the tool's own labels, in its order.
  const VA_STATUSES = [['remediation_required', 'Remediation required'], ['scheduled', 'Scheduled for remediation'], ['pending_client_action', 'Pending client action'], ['pending_vendor_fix', 'Pending vendor fix'], ['mitigation_applied', 'Mitigation applied (per Defender)'], ['mitigation_in_place', 'Mitigation in place'], ['pending_validation', 'Pending validation'], ['resolved', 'Resolved']]
  const OWNERS = { PROVIDER: 'Atmosera', CLIENT: 'Your team', SHARED: 'Atmosera and your team', UNKNOWN: 'To be confirmed' }
  const INDICATOR_KINDS = ['IP address', 'Domain', 'URL', 'File hash', 'Email address', 'Other']
  const SPRAY_TARGETS = 10

  const humanize = value => { const t = clean(value).replace(/([a-z])([A-Z])/g, '$1 $2').toLowerCase(); return t ? t.charAt(0).toUpperCase() + t.slice(1) : 'Not recorded' }
  const techniqueLabel = id => { const parent = id.split('.')[0], name = TECHNIQUES[parent]; return name ? `${name} (${id})` : id }
  const riskLabel = type => RISK_TYPES[String(type ?? '').toLowerCase()] || humanize(type)
  const addDays = (d, n) => { const x = new Date(`${iso(d)}T12:00:00Z`); x.setUTCDate(x.getUTCDate() + n); return x.toISOString().slice(0, 10) }
  const lastDay = key => { const [y, mo] = key.split('-').map(Number); return new Date(Date.UTC(y, mo, 0, 12)).toISOString().slice(0, 10) }
  const shortDate = d => validDate(iso(d)) ? new Date(`${iso(d)}T12:00:00Z`).toLocaleDateString('en-US', { month: 'short', day: 'numeric', timeZone: 'UTC' }) : 'Date not recorded'
  // A neutral month over month change: a count, a duration or a percentage point move, never better or worse.
  const changeOf = (now, before, kind = 'count') => {
    if (now === null || now === undefined || before === null || before === undefined) return ''
    const d = now - before
    if (kind === 'minutes') return Math.abs(d) < 1 ? 'About the same' : `${duration(Math.abs(d))} ${d > 0 ? 'longer' : 'shorter'}`
    if (kind === 'points') return Math.abs(d) < 0.05 ? 'No change' : `${d > 0 ? 'Up' : 'Down'} ${fmt(Math.round(Math.abs(d) * 10) / 10)} points`
    return d === 0 ? 'No change' : `${fmt(Math.abs(d))} ${d > 0 ? 'more' : 'fewer'}`
  }

  function build(data, m) {
    const p = data.parameters || {}
    const results = data.results || {}
    const context = data.context || {}
    const index = new Map(array(data.manifest).map(r => [r.ResultId, r]))
    const state = id => clean(index.get(id)?.Status || 'MISSING')
    const rows = id => ['OK', 'PARTIAL'].includes(state(id)) ? array(results[id]).filter(r => r && typeof r === 'object') : []
    // Measured: a reading was taken, so an empty result is a real zero. A table no workspace holds is not a reading.
    const measured = id => ['OK', 'PARTIAL', 'EMPTY'].includes(state(id)) && !bool(index.get(id)?.NoTable)
    const partial = id => state(id) === 'PARTIAL'
    const source = (id, extra = '') => `${id}. Read ${date(index.get(id)?.ReadTimeUtc)}.${partial(id) ? ' Partial collection scope.' : ''}${extra ? ' ' + extra : ''}`
    const cs = { presenter: [], review: [], unmeasured: [], headline: [], summary: [], highlights: [] }
    const presenter = (title, text) => cs.presenter.push({ title: clean(title), text: clean(text) })
    const note = (title, text) => cs.review.push({ title: clean(title), text: clean(text) })
    const unmeasured = (id, label, reason) => cs.unmeasured.push({ id, label: clean(label), reason: clean(reason) })
    const sumOf = (list, field) => list.reduce((n, r) => n + (num(r[field]) ?? 0), 0)

    // The report month and the months of the window. The report month is the month of the window end. A window that
    // starts after the 1st or ends before the last day leaves the report month partial, and the month says so.
    const windowValid = !!m.period?.valid
    const key = /^\d{4}-\d{2}$/.test(String(p.ReportMonth || '')) ? String(p.ReportMonth) : windowValid ? iso(p.WindowEnd).slice(0, 7) : null
    const monthStart = key ? `${key}-01` : null, monthEnd = key ? lastDay(key) : null
    const inWindow = windowValid && key && monthEnd >= p.WindowStart && monthStart <= p.WindowEnd
    cs.month = {
      key, valid: !!inWindow, start: monthStart, end: monthEnd,
      label: key ? monthName(monthStart) : 'Month not recorded', short: key ? monthLabel(monthStart) : 'Month not recorded',
      partial: !!inWindow && (p.WindowStart > monthStart || p.WindowEnd < monthEnd)
    }
    cs.window = { start: p.WindowStart, end: p.WindowEnd, label: m.period?.label || 'Dates not recorded', days: windowValid ? Math.round((Date.parse(p.WindowEnd) - Date.parse(p.WindowStart)) / 86400000) + 1 : null }
    cs.months = []
    if (windowValid) {
      for (let k = iso(p.WindowStart).slice(0, 7); k <= iso(p.WindowEnd).slice(0, 7);) {
        const start = `${k}-01` < p.WindowStart ? p.WindowStart : `${k}-01`, end = lastDay(k) > p.WindowEnd ? p.WindowEnd : lastDay(k)
        cs.months.push({ key: k, label: monthLabel(`${k}-01`), name: monthName(`${k}-01`), start, end, report: k === key, partial: start !== `${k}-01` || end !== lastDay(k) })
        const [y, mo] = k.split('-').map(Number)
        k = mo === 12 ? `${y + 1}-01` : `${y}-${String(mo + 1).padStart(2, '0')}`
      }
    }
    const reportIndex = cs.months.findIndex(x => x.report)
    const prevMonth = reportIndex > 0 ? cs.months[reportIndex - 1] : null
    if (!cs.month.valid) presenter('Report month', 'The report month could not be placed inside the alert period, so the monthly figures are withheld. Recollect with -ReportMonth, or correct WindowStart and WindowEnd.')
    if (cs.month.partial) presenter('Partial report month', `The alert period ${cs.window.label} covers only part of ${cs.month.label}. Monthly figures for it cover the days inside the period.`)
    if (cs.months.length && cs.months.length < 3) presenter('Shortened trend', `The trend covers ${plural(cs.months.length, 'month', 'months')}, not three, because the alert records start later (${clean(p.WindowBasis || 'window basis not recorded')}).`)
    const monthOf = value => iso(value).slice(0, 7)

    // Security operations, month by month and week by week. The same alert population as OUT.1, and the same gate.
    const alertsAllowed = !!m.alertsAllowed && cs.month.valid
    const ops = cs.ops = { monthly: [], weekly: [], timing: [], types: [], typesWithheld: 0 }
    if (alertsAllowed && measured('OUT.3')) {
      const byMonth = new Map(rows('OUT.3').filter(r => validDate(iso(r.Month))).map(r => [monthOf(r.Month), r]))
      ops.monthly = cs.months.map(mo => { const r = byMonth.get(mo.key) || {}; return { key: mo.key, label: mo.label, report: mo.report, partial: mo.partial, total: count(r.Total) ?? 0, high: count(r.High) ?? 0, medium: count(r.Medium) ?? 0, low: count(r.Low) ?? 0, tp: count(r.TruePositive) ?? 0, fp: count(r.FalsePositive) ?? 0 } })
      ops.monthlySource = source('OUT.3')
    } else unmeasured('OUT.3', 'Alerts created each month', !m.alertsAllowed ? 'the combined alert result is reconciled first' : state('OUT.3'))
    if (alertsAllowed && measured('OUT.3-WEEK')) {
      const byWeek = new Map(rows('OUT.3-WEEK').filter(r => validDate(iso(r.Week))).map(r => [iso(r.Week), r]))
      for (let start = p.WindowStart; start <= p.WindowEnd; start = addDays(start, 7)) {
        const end = addDays(start, 6) > p.WindowEnd ? p.WindowEnd : addDays(start, 6), r = byWeek.get(start) || {}
        const days = Math.round((Date.parse(end) - Date.parse(start)) / 86400000) + 1
        ops.weekly.push({ start, end, days, label: shortDate(start), span: span(start, end), total: count(r.Total) ?? 0, high: count(r.High) ?? 0, medium: count(r.Medium) ?? 0, low: count(r.Low) ?? 0, tp: count(r.TruePositive) ?? 0 })
      }
      ops.weeklySource = source('OUT.3-WEEK')
      const short = ops.weekly.filter(w => w.days < 7)
      if (short.length) ops.weeklyNote = `Weeks run 7 days from ${date(p.WindowStart)}. The last ${short.length === 1 ? 'bin covers' : 'bins cover'} ${list(short.map(w => plural(w.days, 'day', 'days')))}.`
    } else if (m.alertsAllowed) unmeasured('OUT.3-WEEK', 'Alerts created each week', state('OUT.3-WEEK'))
    // Response timing by month: the OUT.2 cohort split by the month the alert was created. A month with fewer than
    // 5 closed alerts in a scope carries no timing for it, and a median under 20 minutes or a 90th percentile over
    // one hour keeps its note, as on the full period.
    if (alertsAllowed && measured('OUT.2-MONTH')) {
      const timing = rows('OUT.2-MONTH')
      const cell = (k, scope) => {
        const r = timing.find(x => monthOf(x.Month) === k && x.Scope === scope)
        const n = count(r?.Incidents) ?? 0
        if (n < TIMING_SAMPLE) return { n, withheld: true }
        const median = num(r.MedianCloseMin), p90 = num(r.P90CloseMin), ack = num(r.MedianTriageMin)
        return { n, withheld: median === null, median, p90, ack, auto: count(r.AutoClosed), belowFloor: median !== null && median < MEDIAN_FLOOR, overHour: p90 !== null && p90 > 60 }
      }
      ops.timing = cs.months.map(mo => ({ key: mo.key, label: mo.label, report: mo.report, high: cell(mo.key, 'High'), all: cell(mo.key, 'All') }))
      ops.timingSource = source('OUT.2-MONTH')
      const flagged = ops.timing.filter(t => !t.high.withheld && (t.high.belowFloor || t.high.overHour))
      if (flagged.length) presenter('Monthly response timing notes', `${list(flagged.map(t => `${t.label} (${[t.high.belowFloor ? `median ${duration(t.high.median)}, under ${MEDIAN_FLOOR} minutes` : '', t.high.overHour ? `90th percentile ${duration(t.high.p90)}, over one hour` : ''].filter(Boolean).join(' and ')})`))}. Each is shown with its note, as the period cohort is. Have the closing breakdown from the tickets ready.`)
    } else if (m.alertsAllowed) unmeasured('OUT.2-MONTH', 'Response timing by month', state('OUT.2-MONTH'))
    // Alert types by title, screened by the builder. Withheld titles are counted, never named.
    if (alertsAllowed && measured('OUT.9')) {
      const byTitle = new Map()
      for (const r of rows('OUT.9')) {
        const title = clean(r.Title || 'Title withheld'), t = byTitle.get(title) || { title: alertWords(title), total: 0, high: 0, tp: 0, month: 0 }
        t.total += count(r.Alerts) ?? 0; t.high += count(r.High) ?? 0; t.tp += count(r.TruePositive) ?? 0
        if (monthOf(r.Month) === key) t.month += count(r.Alerts) ?? 0
        byTitle.set(title, t)
      }
      const withheld = byTitle.get('Title withheld')
      ops.typesWithheld = withheld ? withheld.total : 0
      byTitle.delete('Title withheld')
      ops.types = [...byTitle.values()].sort((a, b) => b.total - a.total || b.high - a.high || a.title.localeCompare(b.title)).slice(0, 8)
      ops.typesSource = source('OUT.9', 'Titles that name an account, address, host or ticket are withheld.')
      if (ops.typesWithheld) presenter('Alert titles withheld', `${plural(ops.typesWithheld, 'alert carries a title', 'alerts carry titles')} that name an account, address, host, path or ticket, so the alert types table counts ${ops.typesWithheld === 1 ? 'it' : 'them'} without the title. The titles are in results/OUT.9.csv of the pack.`)
    }

    // Threat intelligence. TI.0 says which tables Sentinel holds in the window, so an uncollected table never reads as
    // a zero. Without TI.0 every table-dependent measure is not gathered, except the indicators: TI.1 looks back past
    // the window start, so its own rows show the table is held, and without rows it is not gathered.
    const reach = measured('TI.0') ? rows('TI.0') : null
    const held = table => !!reach && reach.some(r => new RegExp(`(?:^|\\.)${table}$`).test(String(r.SourceTable)) && (num(r.Records) ?? 0) > 0)
    const ti = cs.threat = { unmeasured: [] }
    const tiMissing = (id, label, reason) => { ti.unmeasured.push({ id, label: clean(label), reason: clean(reason) }); unmeasured(id, label, reason) }
    // Indicators monitored, by type and feed.
    if (measured('TI.1') && rows('TI.1').length > 0) {
      const r = rows('TI.1')
      const byKind = INDICATOR_KINDS.map(kind => { const k = r.filter(x => (INDICATOR_KINDS.includes(x.Kind) ? x.Kind : 'Other') === kind); return { kind, total: sumOf(k, 'Indicators'), active: sumOf(k, 'Active') } }).filter(k => k.total > 0)
      const feeds = [...r.reduce((acc, x) => acc.set(clean(x.Source) || 'Not recorded', (acc.get(clean(x.Source) || 'Not recorded') || 0) + (num(x.Indicators) ?? 0)), new Map())].map(([name, total]) => ({ name, total })).sort((a, b) => b.total - a.total)
      const latest = r.map(x => iso(x.LastIngested)).filter(validDate).sort().pop() || null
      ti.indicators = { total: sumOf(r, 'Indicators'), active: sumOf(r, 'Active'), byKind, feeds: feeds.slice(0, 5), feedCount: feeds.length, latest: latest ? date(latest) : null, source: source('TI.1') }
    } else tiMissing('TI.1', 'Threat intelligence indicators', !measured('TI.1') ? state('TI.1') : 'Sentinel holds no threat intelligence indicator in the year to the window end')
    // Indicator matches: detections from the threat intelligence analytics rules.
    if (measured('TI.2') && held('SecurityAlert')) {
      const r = rows('TI.2')
      const byMonth = cs.months.map(mo => { const x = r.filter(y => monthOf(y.Month) === mo.key); return { key: mo.key, label: mo.label, report: mo.report, total: sumOf(x, 'Detections'), ticketed: sumOf(x, 'Ticketed') } })
      const byType = INDICATOR_KINDS.map(type => ({ type, total: sumOf(r.filter(x => (INDICATOR_KINDS.includes(x.Indicator) ? x.Indicator : 'Other') === type), 'Detections') })).filter(t => t.total > 0)
      ti.matches = { total: sumOf(r, 'Detections'), ticketed: sumOf(r, 'Ticketed'), month: byMonth.find(x => x.report)?.total ?? 0, high: sumOf(r.filter(x => x.AlertSeverity === 'High'), 'Detections'), byMonth, byType, source: source('TI.2') }
      if (ti.matches.total > 0) presenter('Threat intelligence matches', `${plural(ti.matches.total, 'detection', 'detections')} from the threat intelligence analytics rules in the period, ${fmt(ti.matches.ticketed)} of them in alerts that opened a ticket. A match confirms the indicator was observed in telemetry and is not an investigation finding. Have the indicators and the closing notes of the ticketed ones ready.`)
    } else tiMissing('TI.2', 'Threat intelligence matches', !measured('TI.0') ? `the table reach was not read (TI.0 ${state('TI.0')})` : !held('SecurityAlert') ? 'Sentinel holds no detection records in the window' : state('TI.2'))
    // Attack stages and techniques on the detections the SOC handled.
    if (alertsAllowed && measured('TI.3')) {
      const byTactic = new Map()
      for (const r of rows('TI.3')) {
        const k = String(r.Tactic || '').trim()
        if (!k) continue
        const t = byTactic.get(k) || { tactic: k, label: stageLabel(k), order: stageIndex(k), alerts: 0, month: 0, tp: 0, detections: 0 }
        t.alerts += count(r.Alerts) ?? 0; t.tp += count(r.TruePositiveAlerts) ?? 0; t.detections += count(r.Detections) ?? 0
        if (monthOf(r.Month) === key) t.month += count(r.Alerts) ?? 0
        byTactic.set(k, t)
      }
      ti.stages = { rows: [...byTactic.values()].sort((a, b) => a.order - b.order || a.label.localeCompare(b.label)), source: source('TI.3', 'Tactics Sentinel recorded on the detections in ticketed alerts.') }
      ti.stages.observed = ti.stages.rows.filter(t => t.alerts > 0).length
    } else tiMissing('TI.3', 'Attack stages observed', !m.alertsAllowed ? 'the combined alert result is reconciled first' : state('TI.3'))
    if (alertsAllowed && measured('TI.4')) {
      ti.techniques = { rows: rows('TI.4').filter(r => /^T\d{4}(\.\d{3})?$/.test(String(r.Technique))).map(r => ({ id: r.Technique, label: techniqueLabel(r.Technique), alerts: count(r.Alerts) ?? 0, tp: count(r.TruePositiveAlerts) ?? 0, detections: count(r.Detections) ?? 0 })).sort((a, b) => b.alerts - a.alerts || a.id.localeCompare(b.id)).slice(0, 10), source: source('TI.4') }
    } else if (m.alertsAllowed) tiMissing('TI.4', 'Attack techniques observed', state('TI.4'))
    // Identity threat activity from interactive sign-ins, and the Entra ID Protection risk detections.
    if (measured('TI.5') && held('SigninLogs')) {
      const r = rows('TI.5')
      const byMonth = cs.months.map(mo => { const x = r.find(y => monthOf(y.Month) === mo.key) || {}; return { key: mo.key, label: mo.label, report: mo.report, signIns: count(x.SignIns) ?? 0, failedPassword: count(x.FailedPassword) ?? 0, targeted: count(x.TargetedUsers) ?? 0, lockouts: count(x.Lockouts) ?? 0, blocked: count(x.BlockedByCa) ?? 0, risky: count(x.RiskySignIns) ?? 0, riskyUsers: count(x.RiskyUsers) ?? 0, riskySuccess: count(x.SuccessfulRisky) ?? 0, hidden: count(x.RiskHidden) ?? 0, sprayIps: count(x.SprayIps) ?? 0, sprayDays: count(x.SprayDays) ?? 0 } })
      const signIns = byMonth.reduce((n, x) => n + x.signIns, 0), hidden = byMonth.reduce((n, x) => n + x.hidden, 0)
      // Risk levels need Entra ID P2. When most sign-ins carry the hidden level the tenant cannot see them, so no
      // risky sign-in count is shown rather than a zero.
      ti.identity = { byMonth, riskVisible: signIns > 0 && hidden * 2 < signIns, source: source('TI.5', `Interactive sign-ins. Password spraying is an address failing a password against ${SPRAY_TARGETS} or more accounts in one day.`) }
      if (!ti.identity.riskVisible) note('Sign-in risk levels', 'Most sign-ins carry the hidden risk level, which means the tenant has no Entra ID P2 license or the risk is not shared with the reader. The risky sign-in row is left out rather than shown as zero.')
      const spray = byMonth.find(x => x.report)?.sprayIps ?? 0
      if (spray > 0) presenter('Password spraying signal', `${plural(spray, 'address', 'addresses')} failed a password against ${SPRAY_TARGETS} or more accounts in one day in ${cs.month.label}. This is a signal, not a confirmed attack. Have the blocking or Conditional Access position ready.`)
    } else tiMissing('TI.5', 'Identity threat activity', !measured('TI.0') ? `the table reach was not read (TI.0 ${state('TI.0')})` : !held('SigninLogs') ? 'Sentinel holds no sign-in logs in the window' : state('TI.5'))
    if (measured('TI.5-RISK') && held('AADUserRiskEvents')) {
      const byType = new Map()
      const riskRows = rows('TI.5-RISK').filter(r => !RISK_EXCLUDED.has(String(r.RiskEventType ?? '').toLowerCase()))
      for (const r of riskRows) {
        const label = riskLabel(r.RiskEventType), t = byType.get(label) || { label, total: 0, month: 0, high: 0 }
        t.total += count(r.Detections) ?? 0; t.high += count(r.High) ?? 0
        if (monthOf(r.Month) === key) t.month += count(r.Detections) ?? 0
        byType.set(label, t)
      }
      const typeRows = [...byType.values()].sort((a, b) => b.total - a.total || a.label.localeCompare(b.label))
      ti.risk = { rows: typeRows.slice(0, 8), total: typeRows.reduce((n, t) => n + t.total, 0), month: typeRows.reduce((n, t) => n + t.month, 0), byMonth: cs.months.map(mo => ({ key: mo.key, label: mo.label, total: sumOf(riskRows.filter(r => monthOf(r.Month) === mo.key), 'Detections') })), source: source('TI.5-RISK', 'Microsoft Entra ID Protection.') }
    } else tiMissing('TI.5-RISK', 'Entra ID Protection risk detections', !measured('TI.0') ? `the table reach was not read (TI.0 ${state('TI.0')})` : !held('AADUserRiskEvents') ? 'Sentinel holds no Entra ID Protection risk detections, which need Entra ID P2 and the risk event diagnostic setting' : state('TI.5-RISK'))
    if (measured('TI.6') && held('EmailEvents')) {
      const r = rows('TI.6')
      ti.email = { byMonth: cs.months.map(mo => { const x = r.find(y => monthOf(y.Month) === mo.key) || {}; return { key: mo.key, label: mo.label, report: mo.report, messages: count(x.Messages) ?? 0, phish: count(x.Phish) ?? 0, malware: count(x.Malware) ?? 0, spam: count(x.Spam) ?? 0, blocked: count(x.ThreatsBlocked) ?? 0, delivered: count(x.ThreatsDelivered) ?? 0 } }), source: source('TI.6', 'Inbound mail, Microsoft Defender for Office 365.') }
      const delivered = ti.email.byMonth.find(x => x.report)?.delivered ?? 0
      if (delivered > 0) presenter('Threat email delivered', `${plural(delivered, 'phishing or malware message was', 'phishing or malware messages were')} delivered to the inbox at first delivery in ${cs.month.label}. Post-delivery removal (DP.7) may have taken them back. Have the zero-hour auto purge position ready.`)
    } else tiMissing('TI.6', 'Email threats', !measured('TI.0') ? `the table reach was not read (TI.0 ${state('TI.0')})` : !held('EmailEvents') ? 'Sentinel does not receive EmailEvents from the Microsoft Defender XDR connector' : state('TI.6'))
    if (measured('TI.7')) {
      const r = rows('TI.7').map(x => ({ threat: clean(x.Threat) || 'Not named', detections: count(x.Detections) ?? 0, devices: count(x.Devices) ?? 0, remediated: count(x.Remediated) ?? 0, executing: count(x.WasExecuting) ?? 0 })).sort((a, b) => b.detections - a.detections || a.threat.localeCompare(b.threat))
      ti.malware = { rows: r.slice(0, 8), total: r.reduce((n, x) => n + x.detections, 0), remediated: r.reduce((n, x) => n + x.remediated, 0), executing: r.reduce((n, x) => n + x.executing, 0), families: r.length, source: source('TI.7', 'Microsoft Defender Antivirus on Azure virtual machines, last 30 days.') }
      if (ti.malware.executing > 0) presenter('Malware running when detected', `${plural(ti.malware.executing, 'detection was', 'detections were')} of a threat that was running when Defender found it. Have the investigation notes for those machines ready.`)
    } else tiMissing('TI.7', 'Malware detected on Azure virtual machines', state('TI.7'))

    // Vulnerability management. The imported Atmosera.VulnAssessment runs (VA.RUNS) are the record: they carry the CISA
    // KEV listing, remediation status, ownership and the change between runs. Without them the Defender queries give
    // the current state only.
    const vuln = cs.vuln = { mode: null, runs: [], changes: [], top: [], kev: [], statuses: [], owners: [], defender: null }
    if (measured('VA.RUNS') && rows('VA.RUNS').length) {
      vuln.mode = 'runs'
      vuln.runs = rows('VA.RUNS').filter(r => validDate(iso(r.RunDate))).sort((a, b) => iso(a.RunDate).localeCompare(iso(b.RunDate))).map(r => ({
        date: iso(r.RunDate), label: date(r.RunDate), complete: r.Status === 'Complete', open: count(r.Open) ?? 0, critical: count(r.Critical) ?? 0, high: count(r.High) ?? 0, medium: count(r.Medium) ?? 0, low: count(r.Low) ?? 0,
        vms: count(r.Vms) ?? 0, cves: count(r.Cves) ?? 0, kev: bool(r.KevChecked) ? count(r.KevOpen) : null, kevVms: bool(r.KevChecked) ? count(r.KevVms) : null, kevThisMonth: bool(r.KevChecked) ? count(r.KevAddedInReportMonth) : null,
        exploit: bool(r.ExploitChecked) ? count(r.ExploitOpen) : null, noFix: count(r.NoVendorFix) ?? 0, eos: count(r.EosVms) ?? 0,
        owners: { PROVIDER: count(r.OwnerProvider) ?? 0, CLIENT: count(r.OwnerClient) ?? 0, UNKNOWN: count(r.OwnerUnknown) ?? 0 },
        statuses: VA_STATUSES.map(([k, label]) => ({ key: k, label, n: count(r[`Status_${k}`]) ?? 0 }))
      }))
      vuln.latest = vuln.runs[vuln.runs.length - 1] || null
      vuln.previous = vuln.runs.length > 1 ? vuln.runs[vuln.runs.length - 2] : null
      vuln.source = source('VA.RUNS', 'Atmosera vulnerability assessment.')
      vuln.changes = rows('VA.CHANGE').map(r => ({ from: iso(r.FromRun), to: iso(r.ToRun), label: `${date(r.FromRun)} to ${date(r.ToRun)}`, compared: bool(r.Compared), reason: clean(r.Reason), new: count(r.New), gone: count(r.NoLongerReported), kept: count(r.Persistent), openNew: count(r.OpenNew), openGone: count(r.OpenNoLonger), openNow: count(r.OpenCurrent), openBefore: count(r.OpenEarlier) })).sort((a, b) => a.to.localeCompare(b.to))
      vuln.change = vuln.changes.length ? vuln.changes[vuln.changes.length - 1] : null
      vuln.changeSource = source('VA.CHANGE')
      if (vuln.change && !vuln.change.compared) note('Vulnerability change not compared', `The latest two assessment runs were not compared because the ${vuln.change.reason}. The change counts are left out rather than estimated.`)
      vuln.top = rows('VA.TOP').map(r => ({ product: clean(r.Product), severity: clean(r.Severity), vms: count(r.Vms) ?? 0, findings: count(r.Findings) ?? 0, cves: count(r.Cves) ?? 0, kev: bool(r.Kev), exploit: bool(r.Exploit), cvss: num(r.MaxCvss), fix: r.FixStatus === 'available' ? 'Fix available' : r.FixStatus === 'not_available' ? 'No vendor fix yet' : 'To be confirmed', owner: OWNERS[r.Owner] || OWNERS.UNKNOWN })).slice(0, 8)
      vuln.topSource = source('VA.TOP')
      vuln.kevKnown = measured('VA.KEV')
      vuln.kev = rows('VA.KEV').map(r => ({ product: clean(r.Product), severity: clean(r.Severity), vms: count(r.Vms) ?? 0, findings: count(r.Findings) ?? 0, added: validDate(iso(r.KevDateAdded)) ? date(r.KevDateAdded) : 'Date not recorded', thisMonth: bool(r.AddedThisMonth) }))
      vuln.kevSource = source('VA.KEV', 'CISA Known Exploited Vulnerabilities catalog.')
      if (vuln.latest) {
        vuln.statuses = vuln.latest.statuses.filter(s => s.n > 0)
        vuln.owners = Object.entries(vuln.latest.owners).filter(([, n]) => n > 0).map(([k, n]) => ({ owner: OWNERS[k], n }))
        if (!vuln.latest.complete) presenter('Partial vulnerability assessment', `The latest assessment run (${vuln.latest.label}) left out or had incomplete data for at least one of the subscriptions in this report, so its counts cover the rest. The run metadata names them.`)
        if (vuln.latest.kev === null) note('CISA KEV not checked', 'The latest assessment run did not check the CISA KEV catalog, so no known exploited count is shown. Re-run the assessment with the catalog before presenting the KEV figures.')
        if (vuln.latest.exploit === null) note('Public exploit not checked', 'The latest assessment run had no Defender for Endpoint data for every subscription, so the public exploit count is left out.')
      }
      const skipped = num(p.VulnAssessmentSkipped) ?? 0
      if (skipped > 0) note('Vulnerability runs skipped', `${plural(skipped, 'assessment run was', 'assessment runs were')} given to the import and skipped (dated outside the window, an urgent-only run, another client, or no run metadata). VA.RUNS in the manifest names each.`)
    }
    if (measured('VA.1')) {
      const sev = ['Critical', 'High', 'Medium', 'Low'].map(level => { const r = rows('VA.1').find(x => String(x.VulnerabilitySeverityLevel) === level) || {}; return { level, cves: count(r.Cves) ?? 0, devices: count(r.Devices) ?? 0, exposures: count(r.Exposures) ?? 0, exploitable: count(r.ExploitableCves) ?? 0 } })
      vuln.defender = {
        bySeverity: sev, cves: sev.reduce((n, s) => n + s.cves, 0), exploitable: sev.reduce((n, s) => n + s.exploitable, 0),
        software: rows('VA.2').map(r => ({ name: clean([r.SoftwareVendor, r.SoftwareName].filter(Boolean).join(' ')).replace(/_/g, ' '), devices: count(r.Devices) ?? 0, cves: count(r.Cves) ?? 0, critical: count(r.Critical) ?? 0, high: count(r.High) ?? 0, exploitable: count(r.ExploitableCves) ?? 0 })).slice(0, 8),
        published: cs.months.map(mo => { const r = rows('VA.3').find(x => monthOf(x.Month) === mo.key) || {}; return { key: mo.key, label: mo.label, cves: count(r.Cves) ?? 0, critical: count(r.Critical) ?? 0, high: count(r.High) ?? 0, exploitable: count(r.ExploitableCves) ?? 0 } }),
        publishedKnown: measured('VA.3'), source: source('VA.1', 'Defender vulnerability management, Azure virtual machines, current state.'), softwareSource: source('VA.2'), publishedSource: source('VA.3')
      }
      if (!vuln.mode) vuln.mode = 'defender'
    } else if (!vuln.mode) unmeasured('VA.1', 'Vulnerabilities on Azure virtual machines', state('VA.1'))
    if (!vuln.mode) note('Vulnerability management', 'Neither an imported vulnerability assessment run (VA.RUNS) nor the Defender vulnerability reading (VA.1) is in the pack, so the vulnerability page says the reading is completed in the review. Import the monthly runs with Import-CyberSocVulnAssessment.ps1.')
    else if (vuln.mode === 'defender') note('Vulnerability management source', 'No vulnerability assessment run was imported, so the vulnerability page reads the current state from Defender (VA.1 to VA.3), without the CISA KEV listing, remediation status or change between months. Import the monthly runs with Import-CyberSocVulnAssessment.ps1 for the full page.')

    // Posture over the window: the Defender for Cloud score by month (POS.7) and the tenant Secure Score at the last
    // snapshot of each month (POS.6-TREND), each a percentage of the maximum it was read against.
    const posture = cs.posture = { cloud: [], tenant: [], health: [] }
    const pos7 = rows('POS.7')
    posture.cloud = cs.months.map(mo => { const r = pos7.find(x => monthOf(x.Month) === mo.key); const v = r ? num(r.Percent) : null; return { key: mo.key, label: mo.label, pct: v, max: r ? num(r.Max) : null } })
    posture.cloudSource = source('POS.7')
    const pos6 = rows('POS.6-TREND').filter(r => validDate(iso(r.Date)))
    posture.tenant = cs.months.map(mo => { const r = pos6.filter(x => monthOf(x.Date) === mo.key).sort((a, b) => iso(b.Date).localeCompare(iso(a.Date)))[0]; return { key: mo.key, label: mo.label, pct: r ? num(r.Percent) : null, max: r ? num(r.Max) : null, date: r ? date(r.Date) : null } })
    posture.tenantSource = source('POS.6-TREND')
    posture.health = rows('POS.8').filter(r => validDate(iso(r.Week)) && iso(r.Week) >= addDays(p.WindowStart, -6) && iso(r.Week) <= iso(p.WindowEnd)).map(r => ({ week: iso(r.Week), label: shortDate(r.Week), pct: num(r.PctHealthy) })).filter(r => r.pct !== null).sort((a, b) => a.week.localeCompare(b.week))
    posture.healthSource = source('POS.8')
    // A score move compares readings against the same maximum only, as the EBR report rules require.
    const sameMax = (a, b) => a && b && a.pct !== null && b.pct !== null && a.max !== null && a.max === b.max

    // Month at a glance: the report month beside the months before it, a neutral change from the previous month.
    const g = cs.glance = { months: cs.months.map(mo => mo.label), rows: [] }
    const at = (series, field) => series.map(x => x ? x[field] : null)
    const glance = (label, values, kind, src, fmtValue) => {
      if (!values.some(v => v !== null && v !== undefined)) return
      const now = reportIndex >= 0 ? values[reportIndex] : null, before = reportIndex > 0 ? values[reportIndex - 1] : null
      g.rows.push({ label: clean(label), values: values.map(v => v === null || v === undefined ? 'Not available' : fmtValue ? fmtValue(v) : fmt(v)), change: changeOf(now, before, kind), source: clean(src) })
    }
    if (ops.monthly.length) {
      glance('Alerts created', at(ops.monthly, 'total'), 'count', 'OUT.3')
      glance('High severity alerts', at(ops.monthly, 'high'), 'count', 'OUT.3')
      glance('Confirmed threats', at(ops.monthly, 'tp'), 'count', 'OUT.3')
    }
    if (ops.timing.length) {
      glance('Median time to close, high severity', ops.timing.map(t => t.high.withheld ? null : t.high.median), 'minutes', 'OUT.2-MONTH', duration)
      glance('Median time to acknowledge, high severity', ops.timing.map(t => t.high.withheld ? null : t.high.ack), 'minutes', 'OUT.2-MONTH', duration)
    }
    if (ti.matches) glance('Threat intelligence matches', at(ti.matches.byMonth, 'total'), 'count', 'TI.2')
    if (ti.identity) {
      glance('Failed password sign-ins', at(ti.identity.byMonth, 'failedPassword'), 'count', 'TI.5')
      glance('Password spraying sources', at(ti.identity.byMonth, 'sprayIps'), 'count', 'TI.5')
      if (ti.identity.riskVisible) glance('Medium and high risk sign-ins', at(ti.identity.byMonth, 'risky'), 'count', 'TI.5')
    }
    if (ti.risk) glance('Identity risk detections', at(ti.risk.byMonth, 'total'), 'count', 'TI.5-RISK')
    if (ti.email) glance('Phishing or malware emails', ti.email.byMonth.map(x => x.blocked + x.delivered), 'count', 'TI.6')
    glance('Defender for Cloud score', at(posture.cloud, 'pct'), 'points', 'POS.7', pctText)
    glance('Microsoft Secure Score', at(posture.tenant, 'pct'), 'points', 'POS.6-TREND', pctText)
    // A score change is printed only between readings against the same maximum.
    for (const [labelText, series] of [['Defender for Cloud score', posture.cloud], ['Microsoft Secure Score', posture.tenant]]) {
      const row = g.rows.find(r => r.label === labelText)
      if (row && reportIndex > 0 && series[reportIndex]?.pct !== null && series[reportIndex - 1]?.pct !== null && !sameMax(series[reportIndex], series[reportIndex - 1])) row.change = 'Not compared, the maximum changed'
    }
    if (ops.monthly.length && prevMonth) {
      const now = ops.monthly[reportIndex], before = ops.monthly[reportIndex - 1]
      if (now && before && now.high > before.high) presenter('High severity increase', `High severity alerts rose from ${fmt(before.high)} in ${before.label} to ${fmt(now.high)} in ${now.label}. The month at a glance shows the counts side by side without a judgment. Have the alert types behind the rise ready.`)
    }

    // Reviewed analyst highlights for the month from the context file. Each needs a title, a summary, a reference,
    // the report month it covers and a review date on or after the month end, so a highlight from another month
    // never reaches this report.
    for (const h of array(context.MonthHighlights)) {
      const rec = h && typeof h === 'object' ? h : {}
      const omitted = reason => note('Month highlight needs review', `A context MonthHighlights record was omitted because ${reason}`)
      if (!clean(rec.Title) || !clean(rec.Summary) || !clean(rec.Reference) || !/^\d{4}-\d{2}$/.test(String(rec.Month || '')) || !validDate(iso(rec.Reviewed))) omitted('it lacks a Title, Summary, Reference, Month (yyyy-MM) or Reviewed date.')
      else if (rec.Month !== key) omitted(`it covers ${monthName(`${rec.Month}-01`)} and this report covers ${cs.month.label}.`)
      else if (iso(rec.Reviewed) < monthEnd) omitted(`its review is dated ${date(rec.Reviewed)}, before ${cs.month.label} ended.`)
      else cs.highlights.push({ title: clean(rec.Title), summary: clean(rec.Summary), reference: clean(rec.Reference), reviewed: date(rec.Reviewed) })
    }
    cs.highlights = cs.highlights.slice(0, 4)

    // The tiles of the threat intelligence and vulnerability pages and slides, so both surfaces read the same.
    const periodWord = cs.months.length === 3 ? 'the 90 days' : 'the period'
    ti.tiles = [
      ti.matches ? { value: fmt(ti.matches.month), label: `Threat intelligence matches in ${cs.month.label}`, sub: `${fmt(ti.matches.total)} over ${periodWord}, ${fmt(ti.matches.ticketed)} in alerts that opened a ticket.`, source: ti.matches.source } : null,
      ti.indicators ? { value: fmt(ti.indicators.active), label: 'Active threat indicators monitored', sub: `From ${plural(ti.indicators.feedCount, 'feed', 'feeds')}${ti.indicators.latest ? `, last ingested ${ti.indicators.latest}` : ''}.`, source: ti.indicators.source } : null,
      ti.stages ? { value: fmt(ti.stages.observed), label: 'MITRE ATT&CK tactics on the alerts', sub: `Over ${periodWord}.`, source: ti.stages.source } : null,
      ti.malware ? { value: fmt(ti.malware.total), label: 'Malware detections on Azure virtual machines', sub: `Last 30 days, ${fmt(ti.malware.remediated)} reported remediated by Defender.`, source: ti.malware.source } : ti.risk ? { value: fmt(ti.risk.month), label: `Identity risk detections in ${cs.month.label}`, sub: `${fmt(ti.risk.total)} over ${periodWord}.`, source: ti.risk.source } : null
    ].filter(Boolean)
    if (vuln.mode === 'runs' && vuln.latest) {
      const L = vuln.latest, c = vuln.change
      vuln.tiles = [
        { value: fmt(L.open), label: 'Open vulnerability findings', sub: `On ${plural(L.vms, 'virtual machine', 'virtual machines')}, assessment of ${L.label}.`, source: vuln.source },
        { value: fmt(L.critical + L.high), label: 'Critical and high findings', sub: `${fmt(L.critical)} critical, ${fmt(L.high)} high.`, source: vuln.source },
        L.kev !== null ? { value: fmt(L.kev), label: 'Findings with a CISA KEV-listed CVE', sub: L.kevThisMonth ? `${fmt(L.kevThisMonth)} on a CVE CISA added in ${cs.month.label}.` : `On ${plural(L.kevVms, 'virtual machine', 'virtual machines')}.`, source: vuln.source } : null,
        c && c.compared ? { value: fmt(c.openGone), label: `No longer open since ${date(c.from)}`, sub: `Pending validation. ${plural(c.openNew, 'new open finding', 'new open findings')} in the same time.`, source: vuln.changeSource } : null
      ].filter(Boolean)
    } else if (vuln.mode === 'defender') {
      const D = vuln.defender, now = reportIndex >= 0 ? D.published[reportIndex] : null
      vuln.tiles = [
        { value: fmt(D.bySeverity[0].cves + D.bySeverity[1].cves), label: 'Critical and high CVEs open', sub: 'On Azure virtual machines, current state.', source: D.source },
        { value: fmt(D.exploitable), label: 'CVEs with public exploit code', sub: 'Per Defender, not a CISA KEV listing.', source: D.source },
        D.publishedKnown && now ? { value: fmt(now.cves), label: `CVEs published in ${cs.month.label} and open now`, sub: `${fmt(now.critical)} critical, ${fmt(now.high)} high.`, source: D.publishedSource } : null
      ].filter(Boolean)
    } else vuln.tiles = []

    // Executive tiles for the month. Each names its month or period, and none claims an outcome the evidence lacks.
    const tile = (label, value, sub, src, tone = '') => cs.headline.push({ label: clean(label), value: clean(value), sub: clean(sub), source: clean(src), tone })
    const nowOps = reportIndex >= 0 ? ops.monthly[reportIndex] : null
    if (nowOps) tile(`Alerts created in ${cs.month.label}`, fmt(nowOps.total), `${plural(ops.monthly.reduce((n, x) => n + x.total, 0), 'alert', 'alerts')} over the ${cs.months.length === 3 ? '90 days' : 'period'}. ${plural(nowOps.tp, 'confirmed threat', 'confirmed threats')} this month.`, ops.monthlySource)
    else if (m.alerts) tile('Alerts triaged', fmt(m.alerts.triaged), m.period.label, m.alerts.source)
    const nowTiming = reportIndex >= 0 ? ops.timing[reportIndex] : null
    if (nowTiming && !nowTiming.high.withheld) tile(`Median time to close, high severity, ${cs.month.short}`, duration(nowTiming.high.median), [nowTiming.high.p90 !== null ? `Nine in ten within ${duration(nowTiming.high.p90)}` : '', `Based on ${plural(nowTiming.high.n, 'closed alert', 'closed alerts')}`, nowTiming.high.belowFloor ? `Under ${MEDIAN_FLOOR} minutes, covered in the review` : '', nowTiming.high.overHour ? '90th percentile over one hour, covered in the review' : ''].filter(Boolean).join('. '), ops.timingSource)
    else if (m.response) tile(`${m.response.median.label}, ${cs.months.length === 3 ? '90 days' : 'period'}`, m.response.median.value, [m.response.p90 ? `Nine in ten within ${m.response.p90.value}` : '', nowTiming ? `Fewer than ${TIMING_SAMPLE} closed in ${cs.month.label}` : ''].filter(Boolean).join('. '), m.response.median.source)
    if (ti.matches) tile(`Threat intelligence matches, ${cs.month.short}`, fmt(ti.matches.month), `${fmt(ti.matches.total)} over the ${cs.months.length === 3 ? '90 days' : 'period'}. An indicator observed in telemetry, not an investigation finding.`, ti.matches.source)
    else if (ti.stages && ti.stages.observed) tile('Attack stages observed', fmt(ti.stages.observed), `MITRE ATT&CK tactics on the alerts over the period`, ti.stages.source)
    if (vuln.mode === 'runs' && vuln.latest) tile('Open critical and high vulnerability findings', fmt(vuln.latest.critical + vuln.latest.high), [vuln.latest.kev !== null ? `${fmt(vuln.latest.kev)} with a CISA KEV-listed CVE` : '', `Assessment of ${vuln.latest.label}`].filter(Boolean).join('. '), vuln.source)
    else if (vuln.mode === 'defender') tile('Critical and high CVEs open on Azure virtual machines', fmt(vuln.defender.bySeverity[0].cves + vuln.defender.bySeverity[1].cves), `${fmt(vuln.defender.exploitable)} with public exploit code, current state`, vuln.defender.source)
    else if (m.tenantScore) tile('Microsoft tenant Secure Score', pctText(m.tenantScore.value), `Read ${m.tenantScore.read}`, m.tenantScore.source)
    cs.headline = cs.headline.slice(0, 4)

    // The summary narrative: what the month held, in the evidence's own terms.
    const say = t => { if (t) cs.summary.push(clean(t)) }
    if (nowOps) say(`In ${cs.month.label}, ${plural(nowOps.total, 'alert', 'alerts')} associated with the managed security service ${nowOps.total === 1 ? 'was' : 'were'} created${prevMonth && ops.monthly[reportIndex - 1] ? `, against ${fmt(ops.monthly[reportIndex - 1].total)} in ${prevMonth.name}` : ''}. ${nowOps.tp > 0 ? `The SOC classified ${plural(nowOps.tp, 'of them as a true positive', 'of them as true positives')}.` : 'None of them was classified as a true positive.'}`)
    if (nowTiming && !nowTiming.high.withheld) say(`High severity alerts created in the month closed in a median of ${duration(nowTiming.high.median)} from creation.`)
    const commonest = ti.stages ? ti.stages.rows.filter(t => t.alerts > 0).sort((a, b) => b.alerts - a.alerts || a.order - b.order)[0] : null
    if (commonest) say(`Across the ${cs.months.length === 3 ? '90 days' : 'period'}, the alerts carried ${plural(ti.stages.observed, 'MITRE ATT&CK tactic', 'MITRE ATT&CK tactics')}, most often ${commonest.label.toLowerCase()}. A tactic is a label recorded at detection, not an investigation finding.`)
    if (ti.matches) say(ti.matches.month > 0 ? `Threat intelligence matched known indicators ${plural(ti.matches.month, 'time', 'times')} in your telemetry this month. A match is an observation, not an investigation finding.` : 'No threat intelligence indicator matched your telemetry this month.')
    if (vuln.mode === 'runs' && vuln.latest) say(`The vulnerability assessment of ${vuln.latest.label} reported ${plural(vuln.latest.open, 'open finding', 'open findings')} on ${plural(vuln.latest.vms, 'virtual machine', 'virtual machines')}, ${fmt(vuln.latest.critical)} critical and ${fmt(vuln.latest.high)} high${vuln.latest.kev !== null ? `, ${fmt(vuln.latest.kev)} with a CVE CISA lists as known exploited` : ''}.${vuln.change && vuln.change.compared ? ` Since the assessment of ${date(vuln.change.from)}, ${plural(vuln.change.openNew, 'open finding is', 'open findings are')} new and ${plural(vuln.change.openGone, 'is', 'are')} no longer open, pending validation.` : ''}`)
    else if (vuln.mode === 'defender') say(`Defender reports ${plural(vuln.defender.cves, 'CVE', 'CVEs')} open on Azure virtual machines at collection, ${fmt(vuln.defender.exploitable)} with public exploit code.`)
    cs.whatNext = `The month at a glance with the 90-day trend, what the SOC handled, the threat intelligence observed in your environment, ${vuln.mode ? 'vulnerability management' : 'the vulnerability position'}, the controls we hold this environment to and the proposed hardening roadmap.`

    // Presenter and review boundaries for the CyberSOC pages.
    if (cs.unmeasured.length) note('CyberSOC measures not gathered', `${cs.unmeasured.map(u => `${u.label} (${u.id}: ${u.reason})`).join('. ')}. These pages say the reading is completed in the review, never a zero.`)
    note('Threat intelligence boundaries', 'A threat intelligence match confirms an indicator was observed in telemetry and is not an investigation finding. A CISA KEV listing means CISA has reported exploitation in the wild, not exploitation in this environment. Tactics are detection-time labels on the alerts, not investigation findings.')
    note('Vulnerability change wording', 'A finding the earlier assessment reported and the later one did not is no longer reported (pending validation). The report never calls it remediated or resolved.')
    return cs
  }

  const api = { build, TECHNIQUES, RISK_TYPES, VA_STATUSES, OWNERS, techniqueLabel, riskLabel, changeOf, SPRAY_TARGETS }
  if (typeof module !== 'undefined' && module.exports) module.exports = api
  else root.EbrCyberSoc = api
})(typeof globalThis !== 'undefined' ? globalThis : this)
