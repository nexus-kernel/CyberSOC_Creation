/* Pure report derivation. Shared by the offline HTML and the regression tests.
   Vocabulary: Sentinel incidents are presented as alerts. SecurityAlert records are detections. */
(function (root) {
  'use strict'
  const array = value => Array.isArray(value) ? value : value ? [value] : []
  const num = value => !['number','string'].includes(typeof value) || String(value).trim() === '' ? null : Number.isFinite(Number(value)) && Number(value) >= 0 ? Number(value) : null
  const count = value => num(value) !== null && Number.isInteger(Number(value)) ? Number(value) : null
  const fmt = value => num(value) === null ? 'Not available' : Number(value).toLocaleString('en-US', { maximumFractionDigits: 1 })
  const pct = (good, total, digits = 1) => total > 0 ? Number((100 * good / total).toFixed(digits)) : null
  const pctText = value => value === null ? '' : `${Number(value).toLocaleString('en-US', { maximumFractionDigits: 1 })}%`
  const clean = value => String(value ?? '').replace(/;/g, '.').replace(/[<>]/g, ' ').replace(/[←-⇿⟰-⟿⤀-⥿]/g, '').replace(/[\u{1f000}-\u{1faff}☀-➿️]/gu, '').replace(/\s+/g, ' ').trim()
  const validDate = value => typeof value === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(value) && !Number.isNaN(Date.parse(value)) && new Date(value).toISOString().slice(0, 10) === value
  const iso = value => String(value ?? '').slice(0, 10)
  const toDate = value => new Date(iso(value) + 'T12:00:00Z')
  const date = value => validDate(iso(value)) ? toDate(value).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric', timeZone: 'UTC' }) : 'Date not recorded'
  const monthLabel = value => validDate(iso(value)) ? toDate(value).toLocaleDateString('en-US', { month: 'short', year: 'numeric', timeZone: 'UTC' }) : 'Month not recorded'
  const monthName = value => validDate(iso(value)) ? toDate(value).toLocaleDateString('en-US', { month: 'long', year: 'numeric', timeZone: 'UTC' }) : 'Month not recorded'
  const monthSpan = (start, end) => {
    const a = monthName(start), b = monthName(end)
    if (a === b) return a
    return iso(start).slice(0, 4) === iso(end).slice(0, 4) ? `${toDate(start).toLocaleDateString('en-US', { month: 'long', timeZone: 'UTC' })} to ${b}` : `${a} to ${b}`
  }
  // MITRE ATT&CK tactics in kill-chain order, as Sentinel records them, with the words the report uses.
  const STAGES = [['PreAttack', 'Pre-attack'], ['Reconnaissance', 'Reconnaissance'], ['ResourceDevelopment', 'Resource development'], ['InitialAccess', 'Initial access'], ['Execution', 'Execution'], ['Persistence', 'Persistence'], ['PrivilegeEscalation', 'Privilege escalation'], ['DefenseEvasion', 'Defense evasion'], ['CredentialAccess', 'Credential access'], ['Discovery', 'Discovery'], ['LateralMovement', 'Lateral movement'], ['Collection', 'Collection'], ['CommandAndControl', 'Command and control'], ['Exfiltration', 'Exfiltration'], ['InhibitResponseFunction', 'Inhibit response function'], ['ImpairProcessControl', 'Impair process control'], ['Impact', 'Impact']]
  const stageIndex = t => { const i = STAGES.findIndex(([k]) => k.toLowerCase() === t.toLowerCase()); return i < 0 ? STAGES.length : i }
  const stageLabel = t => STAGES[stageIndex(t)]?.[1] || clean(t).replace(/([a-z])([A-Z])/g, (_, a, b) => `${a} ${b.toLowerCase()}`)
  const SEV_RANK = { High: 0, Medium: 1, Low: 2, Informational: 3 }
  const sevName = s => ['High', 'Medium', 'Low', 'Informational'].find(k => k.toLowerCase() === clean(s).toLowerCase()) || 'Not recorded'
  // Client copy says alerts, never incidents, including inside alert titles such as Multi-stage incident.
  const alertWords = value => clean(value).replace(/\bincident(s?)\b/gi, w => { const r = w.replace(/incident/i, 'alert'); return w === w.toUpperCase() ? r.toUpperCase() : w[0] === 'I' ? r[0].toUpperCase() + r.slice(1) : r })
  const span = (start, end) => {
    if (!validDate(iso(start)) || !validDate(iso(end))) return 'Dates not recorded'
    const a = toDate(start), b = toDate(end)
    if (a.getUTCFullYear() === b.getUTCFullYear()) return `${a.toLocaleDateString('en-US', { month: 'short', day: 'numeric', timeZone: 'UTC' })} to ${b.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric', timeZone: 'UTC' })}`
    return `${date(start)} to ${date(end)}`
  }
  const monthsBetween = (start, end) => {
    const a = toDate(start), b = toDate(end)
    let months = (b.getUTCFullYear() - a.getUTCFullYear()) * 12 + (b.getUTCMonth() - a.getUTCMonth())
    if (b.getUTCDate() < a.getUTCDate()) months -= 1
    return Math.max(0, months)
  }
  const sum = (rows, field) => rows.length && rows.every(r => num(r[field]) !== null) ? rows.reduce((n, r) => n + Number(r[field]), 0) : null
  const duration = value => num(value) === null ? 'Not available' : value < 1 ? 'Under 1 min' : value < 60 ? `${fmt(Math.round(value))} min` : value < 1440 ? `${fmt(Math.round(value / 6) / 10)} hr` : `${fmt(Math.round(value / 144) / 10)} days`
  // Deck thresholds: E at 90 percent or more, P from 50 to 89, N below 50 (set Oct 11, 2026).
  const E_THRESHOLD = 90
  const mark = value => value === null ? null : value >= E_THRESHOLD ? 'E' : value >= 50 ? 'P' : 'N'
  // A ratio control with fewer resources than this, or with more machines left out by tag than assessed, is on a
  // small sample: it keeps its mark and its place in the tier counts, which name it beside the total, and it never
  // leads a pillar or stands as a win. "2 of 2" is accurate but carries no weight beside the figures around it
  // (Oct 18, 2026, issue #24).
  const MIN_SAMPLE = 10
  const smallSampleText = n => `${fmt(n)} on a small sample`
  const bool = value => value === true || String(value ?? '').toLowerCase() === 'true'
  const plural = (n, one, many) => `${fmt(n)} ${n === 1 ? one : many}`
  // Microsoft retires its own text message and voice delivery in two populations: most users on Feb 1, 2027, and
  // Global Administrators and external users on Jul 1, 2027 (internal guests stay in the first). The countdown runs
  // to the first date. Read from learn.microsoft.com concept-sms-voice-retirement, dated Sep 23, 2026 (Oct 16, 2026).
  const RETIREMENT = {
    date: '2027-02-01', label: 'February 1, 2027', short: 'Feb 1, 2027',
    later: { date: '2027-07-01', label: 'July 1, 2027', short: 'Jul 1, 2027', who: 'Global Administrators and external users' },
    text: 'February 1, 2027 (July 1, 2027 for Global Administrators and external users)',
    shortText: 'Feb 1, 2027 (Jul 1, 2027 for Global Administrators and external users)'
  }
  // The reviewed status of a roadmap item or an ask, from the Actions records in the context file. Each record names
  // the item by its key, the same key the story gives the roadmap item and the ask (report/report-story.js, kept in
  // step by tests/ebr-report-story.test.cjs), so later surfaces can read owner, target date and status by key. No
  // surface says scheduled, approved or in progress without a record, and verified needs a Delivered record with the
  // same reference as well (Oct 16, 2026). backupcheck is the backup coverage validation in Now, split from the backup
  // item on Oct 18, 2026 (issue #25). backup keeps the Azure Backup extension and its ask.
  // The MFA method update is measured by what the next collection and the change record can show, never promised
  // as a non-event (Oct 16, 2026).
  const MFA_OUTCOME = `Every affected user registered on a replacement method before ${RETIREMENT.text}, the fallback tested, and no rise in failed sign-ins after enforcement.`
  const ACTION_KEYS = ['drift', 'critical', 'methods', 'access', 'backupcheck', 'idp', 'phish', 'consent', 'workload', 'logging', 'kvrbac', 'diskenc', 'containers', 'vulnassess', 'segment', 'windows', 'backup', 'vmplatform', 'pim', 'allowlist', 'sharing', 'mdi']
  const ACTION_STATUS = { Proposed: 'Proposed', PendingValidation: 'Pending validation', AwaitingApproval: 'Awaiting approval', Approved: 'Approved', Scheduled: 'Scheduled', InProgress: 'In progress', Verified: 'Verified' }
  // A median under the floor and a 90th percentile over one hour are presented with a note, never hidden.
  const MEDIAN_FLOOR = 20
  const TIMING_SAMPLE = 5
  const TIERS = { foundational: 'Foundational', defense: 'Defense in depth' }
  // Network devices and firewall operating systems, which cannot run an endpoint sensor.
  const NETWORK_DEVICE = /palo ?alto|pan-?os|meraki|fortinet|forti(gate|os)|sonicwall|sonicos|watchguard|check ?point|gaia|barracuda/i
  const PRODUCTS = {
    'azure sentinel': 'Sentinel', 'microsoft sentinel': 'Sentinel', 'azure security center': 'Defender for Cloud',
    'microsoft defender advanced threat protection': 'Defender for Endpoint', 'office 365 advanced threat protection': 'Defender for Office 365',
    'azure active directory identity protection': 'Identity Protection', 'microsoft 365 defender': 'Defender XDR',
    'microsoft defender for identity': 'Defender for Identity', 'microsoft cloud app security': 'Defender for Cloud Apps', 'azure advanced threat protection': 'Defender for Identity'
  }
  const product = name => PRODUCTS[String(name ?? '').toLowerCase()] || clean(name)
  const list = items => items.length <= 1 ? items.join('') : `${items.slice(0, -1).join(', ')} and ${items[items.length - 1]}`

  function build(data) {
    const p = data.parameters || {}
    const manifest = array(data.manifest)
    const results = data.results || {}
    const context = data.context || {}
    const index = new Map(manifest.map(r => [r.ResultId, r]))
    const state = id => clean(index.get(id)?.Status || 'MISSING')
    const rows = id => ['OK', 'PARTIAL'].includes(state(id)) ? array(results[id]).filter(r => r && typeof r === 'object') : []
    const one = id => rows(id).length === 1 ? rows(id)[0] : null
    const has = id => ['OK', 'PARTIAL', 'EMPTY'].includes(state(id))
    const partial = id => state(id) === 'PARTIAL'
    const windowValid = validDate(p.WindowStart) && validDate(p.WindowEnd) && p.WindowStart <= p.WindowEnd
    const readDate = date(p.PostureReadDate)
    const m = {
      client: clean(p.ClientName || 'Client security review'),
      period: { start: p.WindowStart, end: p.WindowEnd, label: span(p.WindowStart, p.WindowEnd), months: windowValid ? monthsBetween(p.WindowStart, p.WindowEnd) + 1 : null, valid: windowValid },
      readDate,
      subscriptions: new Set(array(p.Subscriptions).map(s => String(s).toLowerCase())).size,
      workspaces: [...new Map(array(p.Workspaces).map(w => [String(w.CustomerId || w.ResourceId || w.Name).toLowerCase(), w])).values()],
      depth: ['brief', 'balanced', 'detailed'].includes(data.depth) ? data.depth : 'balanced',
      service: null, headline: [], tiers: { outcomes: [], controls: [], hardening: [], benchmark: [] }, tierSummary: null, whatNext: '',
      response: null, alerts: null, threats: null, impact: null, threatMeasures: null, impactStatement: '', detections: null, trend: [], pillars: [], controls: [], priorities: [], delivered: [], actions: [], mfaMethods: null,
      cloudScore: null, tenantScore: null, posture: {}, review: [], presenter: [], unmeasured: [], notApplicable: [], issues: array(data.issues).map(clean),
      manifest: manifest.map(r => ({ id: clean(r.ResultId), status: clean(r.Status), rows: count(r.Rows), date: date(r.ReadTimeUtc) })),
      tenantWorkspace: clean(p.TenantWideTables?.SigninLogs || 'Not recorded'),
      excluded: clean(p.ManagedRgPattern || '')
    }
    const source = (id, extra = '') => `${id}. Read ${date(index.get(id)?.ReadTimeUtc)}.${partial(id) ? ' Partial collection scope.' : ''}${extra ? ' ' + extra : ''}`
    const note = (title, text) => m.review.push({ title: clean(title), text: clean(text) })
    const presenter = (title, text) => m.presenter.push({ title: clean(title), text: clean(text) })
    const unmeasured = (id, label, reason) => m.unmeasured.push({ id, label: clean(label), reason: clean(reason) })

    // Service tenure from the reviewed context file.
    if (validDate(context.ServiceStartDate) && validDate(p.PostureReadDate) && context.ServiceStartDate <= p.PostureReadDate) {
      m.service = { months: monthsBetween(context.ServiceStartDate, p.PostureReadDate), start: date(context.ServiceStartDate) }
    } else if (context.ServiceStartDate) note('Service start date', 'The context ServiceStartDate is missing, malformed or later than the posture read date, so the tenure tile is omitted.')

    // Alert population integrity across workspaces.
    const dup = one('P0.1-XDRDUP')
    const duplicateCount = count(dup?.InMultipleWorkspaces)
    const duplicateSafe = m.workspaces.length <= 1 || (state('P0.1-XDRDUP') === 'OK' && duplicateCount === 0)
    if (!duplicateSafe) {
      presenter('Alert reconciliation required', duplicateCount > 0 ? `${fmt(duplicateCount)} Defender XDR alerts appear in more than one workspace. Alert totals and response timing are withheld until the combined result is reconciled.` : 'Cross-workspace duplication has not been verified. Alert totals and response timing are withheld until the combined result is reconciled.')
    }
    if (dup && count(dup.XdrIncidents) === 0) presenter('Defender XDR scope', 'No Defender XDR alerts reached Sentinel in the collection. Alert figures cover Defender for Cloud, Sentinel analytics and Identity Protection. Endpoint, Office 365 and Identity alerts handled in the Defender portal are not in these counts. Say so if asked, or add portal counts.')
    // The client surfaces state the same scope (Oct 17, 2026). Only a complete reading of zero says Defender XDR alerts
    // are left out. A count above zero shows that some reach Sentinel, never that all do, since P0.1-XDRDUP reads
    // Sentinel alone, so the statement stays qualified, also from a partial reading. A missing or unreadable reading,
    // or a partial zero, says the routing was not read, never that Defender XDR alerts are in.
    const xdrCount = dup ? count(dup.XdrIncidents) : null
    const xdrScope = xdrCount > 0 ? 'received' : xdrCount === 0 && state('P0.1-XDRDUP') === 'OK' ? 'excluded' : 'unknown'
    m.xdrScope = {
      state: xdrScope,
      sentence: xdrScope === 'excluded' ? 'Alerts investigated only in other platforms, including Microsoft Defender XDR, are not included. No Defender XDR alert was found in Sentinel in the year before collection.'
        : xdrScope === 'received' ? 'Alerts investigated only in other platforms, including the Microsoft Defender XDR portal, are not included. Defender XDR alerts are counted where Sentinel received them.'
        : 'Alerts investigated only in other platforms, including Microsoft Defender XDR, may not be included. Whether Defender XDR alerts reach Sentinel was not read in this collection.'
    }
    if (!windowValid) presenter('Period dates', 'The alert period dates are invalid. Outcome figures are withheld until the pack is corrected.')
    const reach = rows('P0.1-BY-WORKSPACE')
    // The SecurityIncident reach row of a workspace that holds alert records, matched on its ID, else its name.
    const alertReach = w => reach.find(r => (r.WorkspaceId ? String(r.WorkspaceId).toLowerCase() === String(w.CustomerId).toLowerCase() : r.Workspace === w.Name) && /(?:^|\.)SecurityIncident$/.test(r.SourceTable) && num(r.Records) > 0)
    if (reach.length) {
      const absent = m.workspaces.filter(w => !alertReach(w)).length
      const late = reach.filter(r => /(?:^|\.)SecurityIncident$/.test(r.SourceTable) && num(r.Records) > 0 && windowValid && validDate(iso(r.EarliestRecord)) && iso(r.EarliestRecord) > p.WindowStart).length
      if (absent) presenter('Workspace coverage', `${plural(absent, 'workspace holds', 'workspaces hold')} no alert records. Figures describe the workspaces that hold data.`)
      if (late) presenter('Workspace start dates', `${plural(late, 'workspace starts', 'workspaces start')} after ${date(p.WindowStart)}. Earlier months reflect the workspaces that were already collecting.`)
    }
    const alertsAllowed = duplicateSafe && windowValid
    m.ticketed = !!clean(p.TicketPattern)
    if (!m.ticketed) presenter('Alert scope', 'This pack was collected before the ticket scope rule. Alert counts include every Sentinel incident, including informational severity and incidents that never opened an Atmosera ticket. Recollect with collector 1.6 or later so only ticketed, non-informational alerts are counted.')
    else note('Alert scope', `Alerts are Sentinel incidents whose comments reference an Atmosera ticket (pattern ${clean(p.TicketPattern)}). Informational severity is excluded. Detections are limited to those linked to these alerts.`)

    // Detections (SecurityAlert records).
    const det = rows('OUT.5')
    const detTotal = windowValid ? sum(det, 'Alerts') : null
    if (detTotal !== null) {
      const bySource = [...det.reduce((acc, r) => acc.set(product(r.ProductName), (acc.get(product(r.ProductName)) || 0) + Number(r.Alerts)), new Map())].map(([name, total]) => ({ name, total })).sort((a, b) => b.total - a.total)
      m.detections = { total: detTotal, bySource, sources: list(bySource.slice(0, 3).map(s => s.name)), allSources: list([...bySource.filter(s => s.name && s.total > 0).map(s => s.name), ...bySource.some(s => !s.name && s.total > 0) ? ['sources not named in the collection'] : []]), source: source('OUT.5', m.ticketed ? 'Detections linked to ticketed alerts.' : '') }
    } else unmeasured('OUT.5', 'Detections received', state('OUT.5'))

    // Alerts (Sentinel incidents) and the automation adjustment.
    const inc = alertsAllowed ? one('OUT.1') : null
    const incValid = inc && ['Raised','Closed','Open'].every(k => count(inc[k]) !== null) && inc.Closed + inc.Open === inc.Raised
    const allRow = alertsAllowed ? rows('OUT.2').find(r => r.Scope === 'All') : null
    const autoValid = allRow && count(allRow.Incidents) !== null && count(allRow.AutoClosed) !== null && allRow.AutoClosed <= allRow.Incidents
    const autoShare = autoValid && allRow.Incidents > 0 ? allRow.AutoClosed / allRow.Incidents : 0
    const analystMode = autoValid && autoShare >= 0.5
    if (incValid) {
      const automation = analystMode ? allRow.AutoClosed : 0
      const triaged = inc.Raised - automation, closed = inc.Closed - automation
      const tp = count(inc.TruePositive)
      // The collector's ExfilOrImpactTactic flag also fires on a Collection tactic. The builder embeds each row's
      // tactics, so the count the report presents is the narrower one, alerts whose tactics include Exfiltration or
      // Impact, and every surface names that scope. A pack whose rows carry no tactics (an older builder, or a
      // flagged row whose tactics could not be read) keeps the flag count and names the wider scope (Oct 14, 2026).
      const flags = has('OUT.4') ? rows('OUT.4') : null
      const tacticsOf = r => String(r.Tactics ?? '').split(',').map(t => t.trim().toLowerCase()).filter(Boolean)
      const tacticsKnown = !!flags && flags.every(r => 'Tactics' in r && (!bool(r.ExfilOrImpactTactic) || tacticsOf(r).length > 0))
      const flagged = flags ? (tacticsKnown ? flags.filter(r => tacticsOf(r).some(t => t === 'exfiltration' || t === 'impact')) : flags.filter(r => bool(r.ExfilOrImpactTactic))).length : null
      const flaggedScope = tacticsKnown ? 'exfiltration or impact' : 'collection, exfiltration or impact'
      // The phrase every surface uses for the count: a tactic recorded on the alert, never an outcome verb such
      // as reached. A true positive is a closure classification, so the surfaces say classified, never
      // investigated, and the impact statement comes only from the reviewed record below (Oct 15, 2026).
      const tacticPhrase = `${/^[aeiou]/.test(flaggedScope) ? 'an' : 'a'} ${flaggedScope} tactic`
      m.alerts = {
        triaged, closed, open: inc.Open, raised: inc.Raised, automation: autoValid ? allRow.AutoClosed : null, analystMode, autoShare: autoValid ? pct(allRow.AutoClosed, allRow.Incidents) : null,
        resolvedPct: pct(closed, triaged), truePositives: tp, benign: count(inc.BenignPositive), falsePositives: count(inc.FalsePositive),
        flagged, flaggedKnown: flagged !== null && tp !== null, flaggedScope, tacticPhrase, unclassified: count(inc.ClosedUnclassified),
        source: source('OUT.1', m.ticketed ? 'Alerts that opened an Atmosera ticket, informational severity excluded.' : ''), partial: partial('OUT.1')
      }
      // Open alerts at collection split into those awaiting the client and those still with Atmosera only from a
      // reviewed OpenAlertNote record in the context file: OUT.1 holds the open count, never who holds each alert.
      // Like the Impact record, the split is bound to the alert period it covers and must account for every open
      // alert, so a context file reused from an earlier period never splits a later count. Without it every surface
      // names both possibilities in one sentence (Oct 16, 2026).
      const openRecord = context.OpenAlertNote
      if (openRecord !== undefined && openRecord !== null && inc.Open > 0) {
        const record = typeof openRecord === 'object' ? openRecord : {}
        const awaiting = count(record.AwaitingClient), inProgress = count(record.InProgress)
        const reviewed = iso(record.Reviewed), recordStart = iso(record.WindowStart), recordEnd = iso(record.WindowEnd)
        const omitted = reason => note('Open alert status needs review', `The context OpenAlertNote record was omitted because ${reason} Correct it before presenting, or remove it to keep the combined open alert sentence.`)
        if (awaiting === null || inProgress === null || awaiting < 0 || inProgress < 0 || !validDate(reviewed) || !clean(record.Reference) || !validDate(recordStart) || !validDate(recordEnd)) omitted('it lacks an AwaitingClient or InProgress count, a Reviewed date, a Reference, or the WindowStart and WindowEnd of the alert period it covers.')
        else if (!windowValid || recordStart !== p.WindowStart || recordEnd !== p.WindowEnd) omitted(`it covers ${span(recordStart, recordEnd)} and this pack's alert period is ${m.period.label}.`)
        else if (reviewed < p.WindowEnd) omitted(`its review is dated ${date(reviewed)}, before the alert period ended on ${date(p.WindowEnd)}.`)
        else if (awaiting + inProgress !== inc.Open) omitted(`it accounts for ${plural(awaiting + inProgress, 'open alert', 'open alerts')} and the pack holds ${fmt(inc.Open)}.`)
        else m.alerts.openSplit = { awaiting, inProgress, reference: clean(record.Reference), reviewed: date(reviewed), source: `Reviewed open alert status ${clean(record.Reference)}, ${date(reviewed)}, from the reviewed context file.` }
      }
      // The sentence every surface uses for the open alerts, after the closed count.
      const were = n => n === 1 ? 'was' : 'were'
      const split = m.alerts.openSplit
      if (split) split.phrase = [split.awaiting > 0 ? `${fmt(split.awaiting)} ${were(split.awaiting)} awaiting client action or confirmation` : '', split.inProgress > 0 ? `${fmt(split.inProgress)} ${were(split.inProgress)} still in progress with Atmosera` : ''].filter(Boolean).join(' and ')
      m.alerts.openSentence = inc.Open > 0 ? `${split ? split.phrase : `${fmt(inc.Open)} ${were(inc.Open)} pending client action, confirmation or continued investigation`} at collection.` : ''
      if (inc.Open > 0) presenter('Open alerts', `${fmt(inc.Open)} of ${fmt(inc.Raised)} alerts created ${m.period.label} were still open at collection. ${split ? `The reviewed record ${split.reference} splits them: ${fmt(split.awaiting)} awaiting client action or confirmation and ${fmt(split.inProgress)} still in progress with Atmosera.` : 'The report describes them as pending client action, confirmation or continued investigation. Add a reviewed OpenAlertNote record to the context file to split them, and have the age and severity split ready if asked.'}`)
      if (count(inc.ClosedUnclassified) > 0) presenter('Closure classification', `${fmt(inc.ClosedUnclassified)} closed alerts carry no definitive classification. The report counts them as closed, never as resolved, and makes no claim about investigation quality.`)
      if (analystMode) presenter('Automation share', `${fmt(allRow.AutoClosed)} of ${fmt(allRow.Incidents)} closed alerts (${pctText(m.alerts.autoShare)}) were closed by automation rules. The headline counts exclude them and the automation volume is shown as a supporting line.`)
      else if (autoValid && autoShare >= 0.25) presenter('Automation share', `${fmt(allRow.AutoClosed)} of ${fmt(allRow.Incidents)} closed alerts (${pctText(m.alerts.autoShare)}) were closed by automation rules. Below the 50 percent threshold, so headline counts include them.`)
    } else if (alertsAllowed) unmeasured('OUT.1', 'Alerts triaged', inc ? 'the combined result does not reconcile' : state('OUT.1'))

    // Confirmed threat examples (OUT.4). The builder embeds a screened title (Threat), the tactics and the day only.
    // Every row is an example, withheld or operational. Withheld covers screened out titles, rows the builder could not
    // screen and staged rows with no title or day. Operational true positives carry no attack stage, such as a service limit warning.
    const threatRows = alertsAllowed && m.alerts ? rows('OUT.4') : []
    if (threatRows.length && !threatRows.some(r => 'Threat' in r)) note('Confirmed threat examples', 'The report data predates confirmed threat examples. Regenerate the report with the current builder to show them.')
    else if (threatRows.length) {
      const stagesOf = r => [...new Set(String(r.Tactics ?? '').split(',').map(t => t.trim()).filter(Boolean))]
      const isWithheld = r => clean(r.Threat) === 'Title withheld'
      const examples = threatRows.filter(r => stagesOf(r).length && clean(r.Threat) && !isWithheld(r) && validDate(iso(r.Created)))
      const operational = threatRows.filter(r => !stagesOf(r).length && !isWithheld(r)).length
      const withheld = threatRows.length - examples.length - operational
      const groups = [...examples.reduce((acc, r) => {
        const key = alertWords(r.Threat)
        return acc.set(key, [...(acc.get(key) || []), r])
      }, new Map())].map(([title, group]) => {
        const days = group.map(r => iso(r.Created)).sort()
        // Stages are joined by commas only, since Command and control already carries an and.
        const stages = [...new Set(group.flatMap(stagesOf).sort((a, b) => stageIndex(a) - stageIndex(b)).map(stageLabel))]
        const severity = group.map(r => sevName(r.Severity)).sort((a, b) => (SEV_RANK[a] ?? 9) - (SEV_RANK[b] ?? 9))[0]
        return { title, alerts: group.length, severity, stage: stages.length > 2 ? `${stages.slice(0, 2).join(', ')}, plus ${plural(stages.length - 2, 'more stage', 'more stages')}` : stages.join(', '), when: monthSpan(days[0], days[days.length - 1]), latest: days[days.length - 1] }
      }).sort((a, b) => (SEV_RANK[a.severity] ?? 9) - (SEV_RANK[b.severity] ?? 9) || b.alerts - a.alerts || b.latest.localeCompare(a.latest) || a.title.localeCompare(b.title, 'en'))
      if (groups.length) {
        const shown = groups.slice(0, 5), more = groups.slice(5)
        const alertsIn = gs => gs.reduce((n, g) => n + g.alerts, 0)
        // Severity is counted per alert before grouping and before the five-group cut, since a group carries its
        // highest severity while its count covers every severity in it.
        const severities = Object.fromEntries(['High', 'Medium', 'Low', 'Informational'].map(k => [k, examples.filter(r => sevName(r.Severity) === k).length]))
        m.threats = { examples: shown.map(({ latest, ...g }) => g), more: more.length, moreAlerts: alertsIn(more), alerts: examples.length, severities, source: source('OUT.4', 'Confirmed threats with an attack stage, grouped by alert title.') }
        presenter('Confirmed threat examples', `The examples use alert titles as Sentinel recorded them, with incident written as alert. Titles that carry an email address, IP address, host or domain name, path, GUID, ticket reference or machine-style name are withheld automatically. Check that no title shown names a person, account or machine, or implies containment, before the review. The table shows ${plural(alertsIn(shown), 'confirmed alert', 'confirmed alerts')} in ${plural(shown.length, 'group', 'groups')}.${more.length ? ` ${fmt(m.threats.moreAlerts)} more ${m.threats.moreAlerts === 1 ? 'sits' : 'sit'} in ${plural(more.length, 'further group', 'further groups')}.` : ''}`)
        // An indicator match (a Log4Shell IP or domain indicator, for example) classified as a true positive confirms
        // the indicator was seen, not that exploitation or compromise occurred. The report draws no distinction.
        const indicators = examples.filter(r => /\b(IOC|IOCs|indicator|indicators|Log4Shell|Log4j|threat intel|threat intelligence)\b/i.test(clean(r.Threat))).length
        presenter('Indicator-based true positives', `A true-positive classification on an indicator detection, such as a Log4Shell IP or domain indicator match, confirms that the indicator was observed, not that exploitation or compromise occurred. The report draws no distinction between an indicator detection and a confirmed exploitation.${indicators ? ` ${fmt(indicators)} of the ${plural(examples.length, 'confirmed alert', 'confirmed alerts')} with an attack stage ${indicators === 1 ? 'carries' : 'carry'} an indicator in the title.` : ''} Have the investigation outcome from each ticket ready if asked.`)
      }
      if (withheld) presenter('Confirmed threat titles withheld', `${plural(withheld, 'confirmed alert is', 'confirmed alerts are')} left out of the examples because ${withheld === 1 ? 'its title may identify' : 'their titles may identify'} an account, address, host or other internal detail, could not be screened, or ${withheld === 1 ? 'carries' : 'carry'} no title or date. The tickets and the pack's OUT.4 result carry the detail.`)
      if (operational) presenter('Operational true positives', `${plural(operational, 'confirmed alert carries', 'confirmed alerts carry')} no attack stage, for example a service limit warning, and ${operational === 1 ? 'is' : 'are'} left out of the confirmed threat examples. The confirmed threat count still includes ${operational === 1 ? 'it' : 'them'}.`)
    }

    // Three measures the surfaces keep apart. Confirmed malicious activity is the true-positive classification
    // count (OUT.1). Confirmed security incidents have no collected or reviewed source, so that measure stays null
    // and no surface prints one. Confirmed business impact comes only from a reviewed determination in the context
    // file (Impact with Confirmed, Reviewed and Reference), never from the tactics Sentinel recorded on an alert:
    // the collector's own OUT.4 note holds that a zero data loss statement needs each flagged closing comment
    // reviewed. Without the record every surface prints the tactic count and asks for additional investigation
    // evidence, and no surface prints reached, no impact or did not reach (Oct 15, 2026).
    // The record is bound to the alert period it covers: it names the period's WindowStart and WindowEnd, its review
    // is dated on or after the period's end, and its count never exceeds the true positives. A context file reused
    // from an earlier period therefore never carries a determination forward to later true positives.
    const impactRecord = context.Impact && typeof context.Impact === 'object' ? context.Impact : null
    if (impactRecord) {
      const confirmed = count(impactRecord.Confirmed)
      const reviewed = iso(impactRecord.Reviewed), recordStart = iso(impactRecord.WindowStart), recordEnd = iso(impactRecord.WindowEnd)
      const omitted = reason => note('Impact determination needs review', `The context Impact record was omitted because ${reason} Correct it before presenting, or remove it to keep the request for additional investigation evidence.`)
      if (confirmed === null || !validDate(reviewed) || !clean(impactRecord.Reference) || !validDate(recordStart) || !validDate(recordEnd)) omitted('it lacks a Confirmed count, a Reviewed date, a Reference, or the WindowStart and WindowEnd of the alert period it covers.')
      else if (!windowValid || recordStart !== p.WindowStart || recordEnd !== p.WindowEnd) omitted(`it covers ${span(recordStart, recordEnd)} and this pack's alert period is ${m.period.label}.`)
      else if (reviewed < p.WindowEnd) omitted(`its review is dated ${date(reviewed)}, before the alert period ended on ${date(p.WindowEnd)}, so it cannot cover every true positive in the period.`)
      else if (m.alerts && m.alerts.truePositives !== null && confirmed > m.alerts.truePositives) omitted(`it confirms impact from ${fmt(confirmed)} alerts against ${fmt(m.alerts.truePositives)} true positives.`)
      else m.impact = { confirmed, reviewed: date(reviewed), reference: clean(impactRecord.Reference), source: `Reviewed impact determination ${clean(impactRecord.Reference)}, ${date(reviewed)}, covering ${m.period.label}, from the reviewed context file.` }
    }
    const tpKnown = !!m.alerts && m.alerts.truePositives !== null
    m.threatMeasures = {
      malicious: tpKnown ? { value: m.alerts.truePositives, label: 'Confirmed threats', detail: 'Alerts the SOC classified as true positives', source: m.alerts.source } : null,
      incidents: null,
      impact: m.impact ? { value: m.impact.confirmed, label: 'Confirmed business impact', detail: `Reviewed ${m.impact.reviewed}, ${m.impact.reference}`, source: m.impact.source } : null
    }
    if (tpKnown && m.alerts.truePositives > 0) {
      const a = m.alerts, tpText = a.truePositives === 1 ? 'the confirmed threat' : `the ${fmt(a.truePositives)} confirmed threats`
      m.impactStatement = clean(m.impact
        ? (m.impact.confirmed === 0 ? `The reviewed investigation records confirm no data exposure or business impact from ${tpText} (${m.impact.reference}, reviewed ${m.impact.reviewed}).` : `The reviewed investigation records confirm data exposure or business impact from ${a.truePositives === 1 ? tpText : `${fmt(m.impact.confirmed)} of ${tpText}`} (${m.impact.reference}, reviewed ${m.impact.reviewed}).`)
        : `${a.flaggedKnown ? `Based on the tactics Sentinel recorded on the alerts, ${a.flagged === 0 ? (a.truePositives === 1 ? 'the confirmed threat did not carry' : 'none of the confirmed threats carried') : `${fmt(a.flagged)} of ${tpText} carried`} ${a.tacticPhrase}. ` : ''}Additional investigation evidence is required to confirm whether any data exposure or business impact occurred.`)
      if (!m.impact) note('Impact determination', 'The context file carries no reviewed Impact record, so the report prints the tactic count with a request for additional investigation evidence and never a data exposure or business impact statement. Review the closing comment and ticket of each true positive, then add Impact with Confirmed, Reviewed, Reference, WindowStart and WindowEnd to the context file to print the determination.')
    }

    // Response timing from one fixed cohort: every eligible high severity alert created in the alert period and closed
    // by collection (OUT.2, row High, which filters on CreatedTime and reads each alert's latest closed state),
    // automation closures included. The cohort never changes with the result, so two reviews compare
    // like for like. A median under 20 minutes and a 90th percentile over one hour are presented with a visible note
    // and a presenter note, never replaced by another cohort or period. The minimum sample of 5 closed alerts is the
    // only rule that withholds the figures, and it does not depend on them. When automation rules closed any of the
    // cohort, the analyst-handled figures (OUT.2-ANALYST) and the automation-closed count sit beside it as two
    // labelled rows. The collector records no timing for automation closures alone, so that row carries the count
    // only (Oct 16, 2026).
    const timingRow = (id, scope) => alertsAllowed ? rows(id).find(r => r.Scope === scope) || null : null
    const timingOf = r => ({ n: count(r?.Incidents), median: num(r?.MedianCloseMin), p90: num(r?.P90CloseMin), triage: num(r?.MedianTriageMin) })
    const FLOOR_NOTE = `Under ${MEDIAN_FLOOR} minutes, covered in the review.`, CEILING_NOTE = 'Over one hour, covered in the review.'
    const highRow = timingRow('OUT.2', 'High'), fixed = timingOf(highRow)
    const cohortLabel = `High severity alerts created ${m.period.label}, closed by collection`
    const timingReason = !alertsAllowed ? '' : !highRow ? `no high severity row in OUT.2 (${state('OUT.2')})` : fixed.n === null || fixed.n < TIMING_SAMPLE ? `${plural(fixed.n ?? 0, 'high severity alert', 'high severity alerts')} closed, below the minimum sample of ${TIMING_SAMPLE}` : fixed.median === null ? 'no median recorded for high severity alerts' : ''
    if (alertsAllowed && !timingReason) {
      const sample = ` Based on ${plural(fixed.n, 'closed alert', 'closed alerts')}.`
      const belowFloor = fixed.median < MEDIAN_FLOOR, overHour = fixed.p90 !== null && fixed.p90 > 60
      m.response = {
        cohort: cohortLabel, scope: 'High', n: fixed.n, key: 'high-full', small: fixed.n < 20,
        median: { value: duration(fixed.median), minutes: fixed.median, belowFloor, label: 'Median time to close, high severity alerts', note: `Creation to recorded close.${sample}${belowFloor ? ` ${FLOOR_NOTE}` : ''}`, source: source('OUT.2') },
        p90: fixed.p90 === null ? null : { value: duration(fixed.p90), minutes: fixed.p90, overHour, label: '90th percentile close, high severity alerts', note: `Nine in ten alerts triaged and closed within this time.${sample}${overHour ? ` ${CEILING_NOTE}` : ''}`, source: source('OUT.2') },
        // MedianTriageMin runs from creation to the first status change away from New, by an analyst or an automation
        // rule, and an alert closed straight from New counts that close.
        acknowledge: fixed.triage === null ? null : { value: duration(fixed.triage), minutes: fixed.triage, label: 'Median time to acknowledge, high severity alerts', note: 'Creation to the first status change from New, by an analyst or an automation rule.', source: source('OUT.2') },
        notes: [belowFloor ? `Median ${FLOOR_NOTE.charAt(0).toLowerCase()}${FLOOR_NOTE.slice(1)}` : '', overHour ? `90th percentile ${CEILING_NOTE.charAt(0).toLowerCase()}${CEILING_NOTE.slice(1)}` : ''].filter(Boolean),
        split: null, target: null
      }
      if (belowFloor) presenter('Median under 20 minutes', `The high severity median time to close is ${duration(fixed.median)}, under the ${MEDIAN_FLOOR} minute presentation floor. It is presented with a note, since the cohort is fixed. A short median often reflects quick benign closures and automation rules, so have the closing breakdown from the tickets ready.`)
      if (overHour) presenter('90th percentile over one hour', `One in ten high severity alerts took longer than ${duration(fixed.p90)} to close. It is presented with a note, since the cohort is fixed. Have the longest running alerts and the reason each stayed open ready.`)
      const auto = count(highRow.AutoClosed)
      if (auto !== null && auto > 0) {
        const analystRow = timingRow('OUT.2-ANALYST', 'High'), a = timingOf(analystRow)
        const analyst = analystRow && a.n !== null ? { label: 'Analyst-handled', n: a.n, median: a.n >= TIMING_SAMPLE && a.median !== null ? { value: duration(a.median), minutes: a.median } : null, p90: a.n >= TIMING_SAMPLE && a.p90 !== null ? { value: duration(a.p90), minutes: a.p90 } : null, acknowledge: a.n >= TIMING_SAMPLE && a.triage !== null ? { value: duration(a.triage), minutes: a.triage } : null, source: source('OUT.2-ANALYST') } : null
        m.response.split = { analyst, automation: { label: 'Closed by automation rules', n: auto, source: source('OUT.2') } }
        presenter('Automation closures in the timing', `Automation rules closed ${fmt(auto)} of the ${plural(fixed.n, 'high severity alert', 'high severity alerts')} in the timing cohort, and the figures include them. ${analyst ? `Analyst-handled alone: ${plural(analyst.n, 'alert', 'alerts')}${analyst.median ? `, median ${analyst.median.value}` : ''}${analyst.p90 ? `, 90th percentile ${analyst.p90.value}` : ''}.` : 'The pack has no analyst-handled high severity result (OUT.2-ANALYST).'} The collector records no time to close for automation closures alone, so that row carries the count only.`)
      }
    } else if (alertsAllowed) unmeasured('OUT.2', 'Response timing', timingReason)
    // The agreed response target (ResponseTargetMinutes in the reviewed context file) is time from creation to
    // recorded close. OUT.2 counts whole minute boundaries per alert and estimates its percentiles, so no share of
    // alerts meeting the target can be read from it. The line compares the reported median and 90th percentile with
    // the target instead, says "about" within a minute of it, and names both limits. Without the field the report
    // prints no target line (Oct 16, 2026).
    const target = context.ResponseTargetMinutes
    if (target !== undefined && target !== null) {
      const minutes = count(target)
      if (minutes === null || minutes < 1) note('Response target needs review', 'The context ResponseTargetMinutes is not a whole number of minutes above zero, so the response target line is omitted. Correct it before presenting, or remove it.')
      else if (m.response) {
        const r = m.response
        const against = v => Math.abs(v.minutes - minutes) <= 1 ? 'about the same as the target' : v.minutes < minutes ? 'under it' : 'over it'
        const parts = [`the median time to close of ${r.median.value} is ${against(r.median)}`, r.p90 ? `the 90th percentile of ${r.p90.value} is ${against(r.p90)}` : ''].filter(Boolean)
        r.target = { minutes, value: duration(minutes), median: against(r.median), p90: r.p90 ? against(r.p90) : null,
          sentence: `Against the agreed ${duration(minutes)} response target, ${parts.join(' and ')}. Close times are recorded in whole minutes and the percentiles are estimates, so this compares the figures with the target and does not count the alerts that met it.`,
          source: 'Response target from the reviewed context file.' }
        presenter('Response target', `The agreed ${duration(minutes)} target is compared with the reported median and 90th percentile only. OUT.2 holds no per-alert close times, so the report gives no share of alerts that met the target and no SLA attainment figure. Have the ticket report ready if the share is asked for.`)
      }
    }
    // The audit trail of the fixed cohort, for the presenter notes only.
    m.timingRationale = alertsAllowed ? [
      { key: 'high-full', cohort: cohortLabel, n: fixed.n, median: fixed.median === null ? null : duration(fixed.median), p90: fixed.p90 === null ? null : duration(fixed.p90), acknowledge: fixed.triage === null ? null : duration(fixed.triage), status: m.response ? ['Presented.', ...m.response.notes].join(' ') : `Not presented: ${timingReason}` },
      ...(m.response?.split ? [
        { key: 'high-analyst', cohort: `${cohortLabel}, analyst-handled`, n: m.response.split.analyst?.n ?? null, median: m.response.split.analyst?.median?.value ?? null, p90: m.response.split.analyst?.p90?.value ?? null, acknowledge: m.response.split.analyst?.acknowledge?.value ?? null, status: m.response.split.analyst ? 'Presented as a labelled row beside the cohort.' : 'Not available: no OUT.2-ANALYST high severity result.' },
        { key: 'high-automation', cohort: `${cohortLabel}, closed by automation rules`, n: m.response.split.automation.n, median: null, p90: null, acknowledge: null, status: 'Presented as a labelled row with the count only. The collector records no timing for automation closures alone.' }
      ] : [])
    ] : []
    // Time to close by severity over the full period, for the deck, from the same OUT.2 rows with automation
    // closures included. Every figure is shown. A severity with fewer than 5 closed alerts carries no timing.
    m.timing = alertsAllowed ? ['High', 'Medium', 'Low', 'All'].map(scope => {
      const t = timingOf(timingRow('OUT.2', scope)), enough = t.n !== null && t.n >= TIMING_SAMPLE
      return { scope, n: t.n, source: source('OUT.2'),
        median: enough && t.median !== null ? { value: duration(t.median), minutes: t.median, belowFloor: t.median < MEDIAN_FLOOR } : null,
        p90: enough && t.p90 !== null ? { value: duration(t.p90), minutes: t.p90, overHour: t.p90 > 60 } : null,
        acknowledge: enough && t.triage !== null ? { value: duration(t.triage), minutes: t.triage } : null }
    }).filter(r => r.n !== null) : []

    // Monthly alert trend.
    const trend = alertsAllowed ? rows('OUT.3').filter(r => validDate(iso(r.Month)) && iso(r.Month) >= p.WindowStart && iso(r.Month) <= p.WindowEnd && ['Total','High','Medium','Low','Informational'].every(k => count(r[k]) !== null)).sort((a, b) => iso(a.Month).localeCompare(iso(b.Month))) : []
    m.trend = trend.map(r => ({ month: iso(r.Month), label: monthLabel(r.Month), Total: r.Total, High: r.High, Medium: r.Medium, Low: r.Low, Informational: r.Informational }))
    m.trendSource = source('OUT.3')
    // Workspace coverage of the months the chart shows (issue #23). P0.1-BY-WORKSPACE gives the first and last alert
    // record each workspace still holds (TimeGenerated), never when collection began: a quiet workspace, or one whose
    // retention is shorter than the window, also starts late. OUT.3 counts each alert in the month it was created, from
    // its latest retained record, so a later update can place an alert in a month before the workspace's first retained
    // record. The client copy therefore states retained record dates only, never which workspaces an alert came from,
    // when collection began or a trend.
    // A workspace counts in a month only when its records span the whole month, so a first record after the 1st or a
    // last record before the month ends leaves that month out. Workspaces with no alert records stay in the
    // denominator. A partial reach reading, or a workspace whose record dates are unreadable, shows no coverage.
    // A pack with one Sentinel workspace has no breakdown: the collector reads P0.1 from that workspace alone.
    m.trendCoverage = null
    const reachId = state('P0.1-BY-WORKSPACE') === 'OK' ? 'P0.1-BY-WORKSPACE' : m.workspaces.length === 1 && state('P0.1-BY-WORKSPACE') === 'MISSING' && state('P0.1') === 'OK' ? 'P0.1' : null
    if (m.trend.length && m.workspaces.length && reachId) {
      const held = reachId === 'P0.1' ? [rows('P0.1').find(r => /(?:^|\.)SecurityIncident$/.test(r.SourceTable) && num(r.Records) > 0)] : m.workspaces.map(alertReach)
      const spans = held.filter(Boolean).map(r => ({ start: iso(r.EarliestRecord), end: iso(r.LatestRecord) }))
      if (spans.every(s => validDate(s.start) && validDate(s.end) && s.start <= s.end)) {
        const monthStart = month => month.slice(0, 7) + '-01'
        const monthEnd = month => new Date(Date.UTC(Number(month.slice(0, 4)), Number(month.slice(5, 7)), 0)).toISOString().slice(0, 10)
        m.trend.forEach(r => { r.workspaces = spans.filter(s => s.start <= monthStart(r.month) && s.end >= monthEnd(r.month)).length })
        const shown = m.trend.slice(-12), total = m.workspaces.length
        if (new Set(shown.map(r => r.workspaces)).size > 1) {
          const first = monthStart(shown[0].month), last = monthEnd(shown[shown.length - 1].month)
          const late = spans.filter(s => s.start > first).length, early = spans.filter(s => s.end < last).length
          const of = n => total === 1 ? 'the Sentinel workspace' : `${fmt(n)} of the ${fmt(total)} Sentinel workspaces`
          // One workspace takes one combined clause: "retained in the Sentinel workspace start after Jul 1, 2026 and end
          // before Sep 30, 2026".
          const both = total === 1 && late && early ? ` and end before ${date(last)}` : early ? `, and in ${fmt(early)} they end before ${date(last)}` : ''
          const dates = late ? `retained in ${of(late)} start after ${date(first)}${both}` : `retained in ${of(early)} end before ${date(last)}`
          // Runs of consecutive months with the same count, for example "3 of 6 in Jul 2026, 6 of 6 in Aug to Sep 2026".
          // OUT.3 has no row for a month without alerts, so a missing month ends a run rather than joining across it.
          const index = month => Number(month.slice(0, 4)) * 12 + Number(month.slice(5, 7))
          const runs = []
          shown.forEach(r => { const run = runs[runs.length - 1]; if (run && run.n === r.workspaces && index(r.month) === index(run.last.month) + 1) run.last = r; else runs.push({ n: r.workspaces, first: r, last: r }) })
          const months = run => {
            if (run.first === run.last) return run.first.label
            const short = month => toDate(month).toLocaleDateString('en-US', { month: 'short', timeZone: 'UTC' })
            return run.first.month.slice(0, 4) === run.last.month.slice(0, 4) ? `${short(run.first.month)} to ${run.last.label}` : `${run.first.label} to ${run.last.label}`
          }
          m.trendCoverage = {
            total, late, early, source: source(reachId),
            sentence: `The alert records ${dates}. Alerts are counted in the month they were created.`,
            caption: `Workspaces whose retained alert records span the whole month: ${runs.map(run => `${fmt(run.n)} of ${fmt(total)} in ${months(run)}`).join(', ')}.`
          }
        }
      }
    }
    if (trend.length >= 2) {
      const first = trend[0], last = trend[trend.length - 1]
      if (last.High > first.High) presenter('High severity trend', `High severity alerts rose from ${fmt(first.High)} in ${monthLabel(first.Month)} to ${fmt(last.High)} in ${monthLabel(last.Month)}. The report presents monthly volume as work absorbed by the SOC and draws no trend conclusion. Be ready to explain the drivers, for example new detections, tuning or a campaign.`)
      if (last.Total > first.Total * 2) presenter('Alert volume', `Monthly alert volume more than doubled between ${monthLabel(first.Month)} and ${monthLabel(last.Month)}. Volume movement is presented as coverage and activity, not as a change in risk.`)
    }

    // Controls with status marks. control() records a measured ratio. inForce() records a verified configuration.
    // ungathered() records a control whose evidence could not be collected. It stays on the client page as (null).
    const NULL_VALUE = '(null)'
    const ungathered = (id, label, where, reason, note) => {
      const item = { id, label: clean(label), ...where, good: null, total: null, pct: null, mark: null, value: NULL_VALUE, measured: false, note: clean(note) || 'Evidence for this control was not gathered in this collection.', source: source(id) }
      m.controls.push(item)
      unmeasured(id, label, reason)
      return item
    }
    const reason = id => state(id) === 'OK' ? 'the result does not contain a valid reading' : state(id)
    const control = (id, label, where, good, total, note, extra = {}) => {
      const ok = count(good) !== null && count(total) !== null && total > 0 && good <= total
      if (!ok && total === 0 && count(good) === 0) {
        note && m.review.push({ title: clean(label), text: `${id}: no applicable resources in scope. The control is omitted from the client page.` })
        return { id, label: clean(label), ...where, good: null, total: null, pct: null, mark: null, value: null, note: clean(note), source: source(id), ...extra }
      }
      if (!ok) return { ...ungathered(id, label, where, reason(id), note), ...extra }
      // A reading at E can still leave resources out. The register counts them as exceptions, so meeting the
      // threshold and having no exceptions read differently (Oct 15, 2026).
      // The excluded count is read only where the collector records one (EW.10-EXCLUDED), so the second rule never
      // fires on a control without it. A verified configuration (inForce) is never on a small sample.
      const grade = mark(pct(good, total))
      const smallSample = total < MIN_SAMPLE || (count(extra.excluded) ?? 0) > total
      const item = { id, label: clean(label), ...where, good, total, pct: pct(good, total), mark: grade, value: `${fmt(good)} of ${fmt(total)}`, exceptions: grade === 'E' ? total - good : 0, smallSample, note: clean(note), source: source(id), ...extra }
      m.controls.push(item)
      return item
    }
    // notApplicable() records a control whose evidence was gathered but holds nothing to judge, for example
    // no device code sign-ins and no policy inventory. It shows as N/A and never moves a count.
    const NA_VALUE = 'N/A'
    const notApplicable = (id, label, where, note) => {
      const item = { id, label: clean(label), ...where, good: null, total: null, pct: null, mark: null, value: NA_VALUE, measured: false, na: true, note: clean(note), source: source(id) }
      m.controls.push(item)
      m.notApplicable.push({ id, label: clean(label) })
      return item
    }
    // A policy control reads In force when the policy covers every user on every application in every condition,
    // and Not in force when no enabled policy requires it. An enabled policy that stops short of that, whether it
    // selects its users or applications or is narrowed by a platform, risk level, device filter or location
    // (condition 'scoped'), reads Mostly enforced, marked P, when the measured sign-in ratio behind it stands at
    // 50 percent or more, and carries that ratio (Oct 14, 2026). The grade rests on the measured ratio, and the
    // note says how the policy is scoped (IA.8-CA ScopeReason, evaluator of Oct 14, 2026 or later).
    const MOSTLY_VALUE = 'Mostly enforced'
    const inForce = (id, label, where, condition, note, ratio = null) => {
      if (condition === null) return ungathered(id, label, where, reason(id), note)
      const on = condition === true
      const mostly = condition === 'scoped' && !!ratio && ratio.pct !== null && ratio.pct >= 50
      const item = { id, label: clean(label), ...where, good: mostly ? ratio.good : null, total: mostly ? ratio.total : null, pct: on ? 100 : mostly ? ratio.pct : 0, mark: on ? 'E' : mostly ? 'P' : 'N', value: on ? 'In force' : mostly ? MOSTLY_VALUE : 'Not in force', boolean: true, note: clean(note), source: source(id) }
      if (mostly) item.ratioText = `${fmt(ratio.good)} of ${fmt(ratio.total)}`
      m.controls.push(item)
      return item
    }
    const isInForce = c => !!c && c.boolean === true && c.value === 'In force'
    // Every, all and none are earned only when nothing is left out: a ratio whose good equals its total, or a policy
    // in force. E at 90 percent or more is a band, not the absence of exceptions (Oct 15, 2026).
    const complete = c => !!c && c.pct !== null && (c.boolean ? isInForce(c) : c.good === c.total)
    // The condition for a Conditional Access flow: true when an enabled policy covers everyone, 'scoped' when
    // an enabled policy covers selected users, applications or conditions only, otherwise false.
    const flowCondition = f => enforcedState(f) ? true : String(f.PolicyState) === 'Scoped' ? 'scoped' : false
    // Placement: every control sits in a pillar (group) and a tier. Foundational controls are the baseline the
    // service holds every environment to and are expected at E at every review. Defense in depth controls are
    // the additional safeguards sequenced afterward. Placement follows docs/MXDR Security Controls Baseline and Hardening.md.
    const G = { identity: 'Identity and access', endpoint: 'Endpoint and workload', network: 'Network and boundary', data: 'Data protection', detection: 'Detection and response' }
    const F = Object.fromEntries(Object.entries(G).map(([k, group]) => [k, { group, tier: 'foundational' }]))
    const D = Object.fromEntries(Object.entries(G).map(([k, group]) => [k, { group, tier: 'defense' }]))

    // Identity and access.
    const member = rows('IA.1').find(r => String(r.UserType).toLowerCase() === 'member')
    const externalMfa = count(member?.UsersExternalMfa)
    const legacyMfaQuery = member && member.UsersExternalMfa === undefined && member.UsersEntraMfa === undefined
    // Collector 1.12.0 classifies each sign-in by its strongest MFA evidence and leaves Windows logon out.
    const evidenceQuery = !!member && member.NoMfaOnlyUnevaluated !== undefined
    // Federated tenants (IA.1-FEDERATION, collector 1.12.0). Most member sign-ins reuse the device session from
    // Windows logon and never return to the identity provider, and Entra records whether such a session carried
    // MFA only when a Require MFA policy asks. A member whose only sign-ins were those sessions is not evaluated,
    // not missing MFA, so the grade leaves them out. Without the Graph read, federated sign-ins in IA.1 decide.
    const federation = one('IA.1-FEDERATION')
    const fedDomains = count(federation?.FederatedDomains)
    const fedProviders = String(federation?.Provider ?? '').split(', ').filter(p => p && !['Other', 'Unknown'].includes(p))
    const federated = fedDomains > 0 || (!has('IA.1-FEDERATION') && (count(member?.FederatedMfaAtLeastOnce) > 0 || count(member?.FederatedWithoutMfa) > 0))
    const unevaluated = federated ? count(member?.NoMfaOnlyUnevaluated) : null
    const evaluated = unevaluated !== null && count(member?.UsersSignedIn) !== null ? member.UsersSignedIn - unevaluated : null
    // The client surfaces state who the grade covers (issue #21): of the members who signed in, how many could be
    // evaluated, how many of those showed MFA on their own sign-ins and how many only by inference from an earlier
    // MFA sign-in in the same session (MfaSessionLinkedOnly, collector 1.13.0, part of UsersChallenged), and how
    // many were not evaluated. A tenant with nothing unevaluated and nothing inferred keeps its plain reading.
    const signedIn = count(member?.UsersSignedIn), challenged = count(member?.UsersChallenged)
    const sessionLinked = count(member?.MfaSessionLinkedOnly)
    const base = evaluated ?? signedIn
    const splitOk = signedIn !== null && challenged !== null && base > 0 && challenged <= base
    const inferred = splitOk && sessionLinked > 0 && sessionLinked <= challenged ? sessionLinked : 0
    const notEvaluated = splitOk && evaluated !== null && unevaluated > 0 ? unevaluated : 0
    const ownSplit = inferred ? `, ${fmt(challenged - inferred)} on their own sign-ins and ${fmt(inferred)} inferred from an earlier MFA sign-in in the same session` : ''
    // The note states why the unevaluated members are not missing MFA, and the pillar narrative says it in short.
    const splitOf = why => !notEvaluated && !inferred ? ''
      : notEvaluated ? `Of ${fmt(signedIn)} members who signed in over the last 30 days, ${fmt(evaluated)} could be evaluated. ${fmt(challenged)} of them showed multifactor authentication${ownSplit}. ${plural(notEvaluated, 'member', 'members')} signed in only through device sessions that no Conditional Access policy checked and ${notEvaluated === 1 ? 'is' : 'are'} ${why ? 'recorded as not evaluated, not as missing multifactor authentication' : 'not evaluated'}.`
      : `${fmt(challenged)} of ${fmt(signedIn)} members who signed in over the last 30 days showed multifactor authentication${ownSplit}.`
    const mfaSplit = splitOf(true), mfaSplitNarrative = splitOf(false)
    // The same split in short, for the deck register detail line.
    const mfaSplitShort = [notEvaluated ? `${fmt(evaluated)} of ${fmt(signedIn)} members evaluated` : '', inferred ? `${fmt(inferred)} inferred from an earlier MFA sign-in in the same session` : ''].filter(Boolean).join(' · ')
    const mfaLabel = 'Multifactor authentication required at sign-in'
    const mfaNote = unevaluated !== null
      ? `Members with at least one successful sign-in in the last 30 days that carried multifactor authentication, out of the members whose sign-ins could be evaluated.${externalMfa > 0 ? ` ${plural(externalMfa, 'member', 'members')} satisfied it through the federated identity provider.` : ''} Windows logon is left out because a federated Windows logon cannot carry multifactor authentication.${notEvaluated ? '' : ' Members whose only sign-ins reused a device session that no Conditional Access policy checked are recorded as not evaluated, not as missing multifactor authentication.'}${mfaSplit ? ` ${mfaSplit}` : ''}`
      : `Members with at least one successful sign-in in the last 30 days that satisfied multifactor authentication.${externalMfa > 0 ? ` ${plural(externalMfa, 'user', 'users')} satisfied it through a federated identity provider claim.` : ''}${evidenceQuery ? ' Windows logon and device registration are left out.' : ''}${mfaSplit ? ` ${mfaSplit}` : ''}`
    // Conditional Access controls. IA.8-CA is evaluated by the report builder from the raw policies and
    // the per-account sign-in detail, and carries counts only. A successful sign-in by an account the
    // policy excludes is an approved exception, not a gap. Without a policy inventory and without any
    // sign-in of the kind, there is no evidence either way and the control reads N/A.
    const caFlows = array(results['IA.8-CA'])
    const caFlow = name => caFlows.find(r => r.Flow === name && bool(r.PolicyRead) && String(r.PolicyState) !== 'Unknown') || null
    const enforcedState = f => ['Enforced', 'Security defaults'].includes(String(f.PolicyState))
    // A scoped policy is described from the reason the evaluator recorded. A policy scoped to selected applications
    // never reads as requiring the control on every application: the application phrase is dropped from the sentence.
    const scopedText = (f, what, verb) => {
      const base = what.replace(/ on (?:every|the Microsoft admin) (?:application|portals)$/, '')
      return ({
        'Conditions': `The enabled Conditional Access policy that ${verb} ${what} applies under selected conditions only, such as a platform, risk level, device filter or location.`,
        'Users': `The enabled Conditional Access policy that ${verb} ${what} applies to selected users only.`,
        'Applications': `The enabled Conditional Access policy that ${verb} ${base} applies to selected applications only.`,
        'UsersAndApplications': `The enabled Conditional Access policy that ${verb} ${base} applies to selected users and selected applications only.`,
        // One enabled policy selects its applications for all users and another selects its users (Oct 16, 2026).
        'UsersOrApplications': `Some of the enabled Conditional Access policies that ${verb.replace(/s$/, '')} ${base} apply to all users on selected applications only, and others to selected users only.`
      })[String(f.ScopeReason)] || `The enabled Conditional Access policy that ${verb} ${what} applies to selected users, applications or conditions only.`
    }
    const policyText = (f, what, verb = 'blocks', who = 'for all users') => ({
      'Enforced': `An enabled Conditional Access policy ${verb} ${what} ${who}.`,
      'Security defaults': `Security defaults ${verb === 'blocks' ? 'block' : 'require'} ${what}.`,
      'Scoped': scopedText(f, what, verb),
      'Report-only': `The Conditional Access policy that ${verb} ${what} runs in report-only mode.`,
      'None': `No Conditional Access policy ${verb} ${what}.`
    })[String(f.PolicyState)] || ''
    const exceptionText = f => {
      if (!f || !bool(f.DetailRead)) return ''
      const parts = []
      if (count(f.SucceededExcluded) > 0) parts.push(`${plural(f.SucceededExcluded, 'successful sign-in', 'successful sign-ins')} came from ${plural(f.AccountsExcluded, 'account', 'accounts')} the policy excludes as approved exceptions.`)
      if (count(f.SucceededUngoverned) > 0) parts.push(`${plural(f.SucceededUngoverned, 'successful sign-in', 'successful sign-ins')} from ${plural(f.AccountsUngoverned, 'account was', 'accounts were')} not covered by the policy.`)
      return parts.join(' ')
    }
    // MFA at sign-in is a Conditional Access control (Oct 14, 2026). When the policy inventory was read, the
    // policy decides the status: an enabled policy requiring MFA on every application for all users, or
    // security defaults, reads In force. The sign-in evidence then supports the note. Packs with no policy
    // inventory keep the sign-in ratio.
    const mfaFlow = caFlow('MFA at sign-in')
    const mfaPolicy = mfaFlow ? policyText(mfaFlow, 'multifactor authentication on every application', 'requires') : ''
    const mfaSignIns = mfaSplit || (evaluated !== null && count(member?.UsersChallenged) !== null ? `${fmt(member.UsersChallenged)} of ${fmt(evaluated)} members whose sign-ins in the last 30 days could be evaluated satisfied it.`
      : count(member?.UsersSignedIn) > 0 && count(member?.UsersChallenged) !== null ? `${fmt(member.UsersChallenged)} of ${fmt(member.UsersSignedIn)} members who signed in over the last 30 days satisfied it.` : '')
    // The sign-in ratio behind the policy status, for the pillar page, the priorities and the Mostly enforced reading.
    const mfaRatio = count(member?.UsersChallenged) !== null && (evaluated ?? count(member?.UsersSignedIn)) > 0 ? { good: member.UsersChallenged, total: evaluated ?? member.UsersSignedIn, pct: pct(member.UsersChallenged, evaluated ?? member.UsersSignedIn) } : null
    const mfa = mfaFlow ? inForce('IA.1', mfaLabel, F.identity, flowCondition(mfaFlow), [mfaPolicy, mfaSignIns, exceptionText(mfaFlow)].filter(Boolean).join(' '), mfaRatio)
      : !member && has('IA.1') ? notApplicable('IA.1', mfaLabel, F.identity, 'No member sign-ins were recorded in the last 30 days, so there is no evidence either way.')
      : evaluated === 0 ? notApplicable('IA.1', mfaLabel, F.identity, 'Every member sign-in in the last 30 days reused a device session that no Conditional Access policy checked, so the logs hold no evidence either way.')
      : control('IA.1', mfaLabel, F.identity, member?.UsersChallenged, evaluated ?? member?.UsersSignedIn, mfaNote, unevaluated !== null ? { population: 'Members whose sign-ins in the last 30 days could be evaluated.' } : {})
    // The register reads the share against the members evaluated, and the deck register carries the split.
    if (mfa.mark && unevaluated !== null) mfa.per = 'of members evaluated'
    if (mfa.mark && mfaSplitShort) mfa.split = mfaSplitShort
    const scopedHow = f => String(f?.ScopeReason) === 'UsersOrApplications' ? 'some enabled policies are limited to selected applications and others to selected users,'
      : `the enabled policy ${({ Conditions: 'applies under selected conditions only', Users: 'applies to selected users only', Applications: 'applies to selected applications only', UsersAndApplications: 'applies to selected users and selected applications only' })[String(f?.ScopeReason)] || 'applies to selected users, applications or conditions only'}`
    if (mfaFlow && mfaRatio && mfaRatio.pct < E_THRESHOLD) presenter('MFA at sign-in', `The control reads ${mfa.value.toLowerCase()} from the Conditional Access policy${mfa.value === MOSTLY_VALUE ? `, because ${scopedHow(mfaFlow)} and the sign-in ratio stands at or above 50 percent` : ''}. The sign-in logs show ${fmt(mfaRatio.good)} of ${fmt(mfaRatio.total)} members with multifactor authentication in the last 30 days${unevaluated !== null ? ', among members whose sign-ins could be evaluated' : ''}. Be ready to explain the difference, for example exclusions, service accounts or sign-ins made before the policy existed.`)
    if (legacyMfaQuery) presenter('MFA coverage query', 'This pack was collected before IA.1 recognised MFA satisfied by external identity provider claims. In a federated tenant the member figure can read far below true coverage. Recollect with the current collector before presenting identity coverage.')
    else if (member && !evidenceQuery && externalMfa > 0) presenter('MFA coverage query', 'This pack was collected before collector 1.12.0. In a federated tenant, members whose only sign-ins reused a device session that no policy checked read here as missing multifactor authentication, although the logs hold no evidence either way. Recollect with the current collector before presenting identity coverage.')
    const noBlockEvidence = 'No attempt reached a Conditional Access block and there is no policy inventory, so there is no evidence either way.'
    // Location-based sign-in access (IA.4-LOCATION) replaced the share of sign-ins Conditional Access evaluated on
    // Oct 12, 2026. Graded from the raw policies: an enabled policy with a country or named network condition that
    // blocks access or requires multifactor authentication, for all users and all resources.
    const locLabel = 'Location-based sign-in access controls enforced through Conditional Access'
    const locFlow = caFlow('Location')
    const locSource = has('IA.8-POLICIES') ? 'IA.8-POLICIES' : 'IA.8'
    const locControl = locFlow ? inForce('IA.4-LOCATION', locLabel, F.identity, enforcedState(locFlow), policyText(locFlow, 'sign-ins by location', 'restricts'))
      : ungathered('IA.4-LOCATION', locLabel, F.identity, caFlows.some(r => r.Flow === 'Location') ? 'the policy inventory in this pack predates collector 1.10.0 and does not record location conditions' : reason(locSource), 'An enabled Conditional Access policy blocks sign-ins or requires multifactor authentication by country or named network, for all users and all resources.')
    locControl.source = `IA.4-LOCATION from ${source(locSource)}`
    if (locFlow && enforcedState(locFlow) && count(locFlow.ExcludedIdentities) > 0) presenter('Location policy exceptions', `${plural(locFlow.ExcludedIdentities, 'user, group or role is', 'users, groups or roles are')} excluded from the location policy. Confirm each is an approved exception, such as emergency access or a travel group, before presenting the control.`)
    const legacyLabel = 'Legacy authentication blocked'
    const legacyFlow = caFlow('Legacy authentication')
    // Unknown is not a legacy protocol. Packs before collector 1.10.0 still carry it as an IA.3 row.
    const legacy = rows('IA.3').filter(r => count(r.Attempts) !== null && count(r.Succeeded) !== null && !/^unknown$/i.test(String(r.ClientAppUsed ?? '')))
    const legacyAttempts = legacy.length ? sum(legacy, 'Attempts') : 0, legacySucceeded = legacy.length ? sum(legacy, 'Succeeded') : 0
    // Only error 53003 is a Conditional Access block. Attempts that failed without one (a wrong password, a locked
    // account, a security defaults block logged as 530035) are never presented as blocked (Oct 14, 2026).
    const legacyBlocked = legacy.reduce((n, r) => n + (count(r.BlockedByCa) ?? 0), 0)
    const legacyFailedEarly = Math.max(0, legacyAttempts - legacySucceeded - legacyBlocked)
    // Without per-account detail (packs before collector 1.10.0), a policy that blocks the flow for all users
    // and all apps means every successful sign-in came from an account outside its scope.
    const outsideScope = f => f && !bool(f.DetailRead) && String(f.PolicyState) === 'Enforced'
    const outsideText = n => n > 0 ? `${plural(n, 'successful sign-in', 'successful sign-ins')} came from ${n === 1 ? 'an account' : 'accounts'} outside the policy scope.` : ''
    const legacyActivity = !has('IA.3') ? '' : legacyAttempts === 0 ? 'No legacy protocol sign-in attempts in the last 30 days.'
      : `${plural(legacyAttempts, 'legacy protocol attempt', 'legacy protocol attempts')} in the last 30 days${legacyBlocked > 0 ? `. Conditional Access stopped ${fmt(legacyBlocked)} and` : ','} ${legacySucceeded > 0 ? `${fmt(legacySucceeded)} succeeded` : 'none succeeded'}.`
    // A pack without the BlockedByCa column cannot tell blocks from other failures, so it raises no note.
    if (legacyFailedEarly > 0 && legacy.every(r => count(r.BlockedByCa) !== null)) presenter('Legacy sign-ins that failed without a Conditional Access block', legacyFlow && String(legacyFlow.PolicyState) === 'Security defaults'
      ? `${plural(legacyFailedEarly, 'legacy protocol attempt', 'legacy protocol attempts')} failed without a Conditional Access block. Security defaults record their own block as error 530035, which this pack does not count separately, so these failures cannot be split between security defaults blocks and wrong passwords.`
      : `${plural(legacyFailedEarly, 'legacy protocol attempt', 'legacy protocol attempts')} failed without a Conditional Access block, most often on a wrong password or a locked account. They are not presented as blocked. A large number points to password spraying against legacy endpoints.`)
    let legacyControl
    if (legacyFlow) {
      // The policy configuration decides the status. Sign-ins show whether any account got past it.
      legacyControl = inForce('IA.3', legacyLabel, F.identity, enforcedState(legacyFlow), [policyText(legacyFlow, 'legacy authentication'), legacyActivity, exceptionText(legacyFlow), outsideScope(legacyFlow) ? outsideText(legacySucceeded) : ''].filter(Boolean).join(' '))
      if (enforcedState(legacyFlow) && bool(legacyFlow.DetailRead) && count(legacyFlow.SucceededUngoverned) > 0) presenter('Legacy sign-ins outside the block policy', `${plural(legacyFlow.SucceededUngoverned, 'successful legacy sign-in', 'successful legacy sign-ins')} in the last 30 days were not evaluated by the enabled block policy. They most likely predate the policy. Confirm before presenting the control. The SecOps worklist names the accounts.`)
    } else if (!has('IA.3')) legacyControl = ungathered('IA.3', legacyLabel, F.identity, reason('IA.3'), 'An enabled Conditional Access policy or security defaults block legacy authentication for all users, with approved exceptions only.')
    else if (legacyAttempts === 0) legacyControl = notApplicable('IA.3', legacyLabel, F.identity, 'No legacy protocol sign-in attempts in the last 30 days and no Conditional Access policy inventory, so there is no evidence either way.')
    else if (legacySucceeded > 0) {
      legacyControl = inForce('IA.3', legacyLabel, F.identity, false, legacyActivity)
      presenter('Legacy authentication exclusions not checked', `${plural(legacySucceeded, 'legacy protocol sign-in', 'legacy protocol sign-ins')} succeeded, but this pack has no Conditional Access policy inventory, so accounts excluded from the block policy could not be told apart from a gap. Recollect with collector 1.10.0 or later and Policy.Read.All before presenting the control.`)
    } else if (legacyBlocked > 0) legacyControl = inForce('IA.3', legacyLabel, F.identity, true, legacyActivity)
    else legacyControl = notApplicable('IA.3', legacyLabel, F.identity, `${legacyActivity} ${noBlockEvidence}`)
    const phish = rows('IA.9').filter(r => r.Enabled === true || String(r.Enabled).toLowerCase() === 'true')
    const advancedPhish = phish.some(r => [r.EnableTargetedUserProtection, r.EnableOrganizationDomainsProtection, r.EnableMailboxIntelligenceProtection, r.EnableSpoofIntelligence].every(v => v === true || String(v).toLowerCase() === 'true'))
    // Foundational: the Microsoft default anti-phishing policy is enabled, so every mailbox has baseline spoof protection.
    // Packs collected before the IsDefault field was selected read any enabled policy as the baseline.
    const phishKnowsDefault = rows('IA.9').some(r => r.IsDefault !== undefined && r.IsDefault !== null)
    const basicPhish = phishKnowsDefault ? phish.some(r => bool(r.IsDefault)) : phish.length > 0
    inForce('IA.9', 'Anti-phishing policy applied to every mailbox', F.identity, has('IA.9') ? basicPhish : null, 'The Microsoft default anti-phishing policy is enabled, so every mailbox carries baseline spoof protection.')
    // Defense in depth: a custom or preset policy adds impersonation and mailbox intelligence protection.
    inForce('IA.9', 'Advanced anti-phishing policy applied', D.identity, has('IA.9') ? advancedPhish : null, 'An enabled anti-phishing policy with impersonation, mailbox intelligence and spoof protection.')
    const roles = one('IA.6-SUB')
    const adminPortal = rows('IA.1-ADMINPORTAL').find(r => String(r.UserType).toLowerCase() === 'member')
    const portalLabel = 'Multifactor authentication at admin portal sign-in'
    const portalFlow = caFlow('Admin portals')
    const portalPolicy = portalFlow ? policyText(portalFlow, 'multifactor authentication on the Microsoft admin portals', 'requires', 'for administrators') : ''
    // Same rule as IA.1: in a federated tenant, members whose only portal sign-ins were unevaluated sessions are left out.
    const portalUnevaluated = federated ? count(adminPortal?.NoMfaOnlyUnevaluated) : null
    const portalUsers = count(adminPortal?.Users)
    const portalTotal = portalUnevaluated !== null && portalUsers !== null ? portalUsers - portalUnevaluated : portalUsers
    const portalSkipped = portalUnevaluated > 0 ? ' Members whose only portal sign-ins reused a session that no Conditional Access policy checked are recorded as not evaluated.' : ''
    // The policy decides the status when the inventory was read (Oct 14, 2026). The sign-ins support the note.
    const portalSignIns = adminPortal && portalTotal > 0 && count(adminPortal.UsersChallenged) !== null ? `${fmt(adminPortal.UsersChallenged)} of ${fmt(portalTotal)} members who signed in to a Microsoft admin portal in the last 30 days satisfied it on at least one of those sign-ins.${portalSkipped}` : ''
    const portalRatio = adminPortal && portalTotal > 0 && count(adminPortal.UsersChallenged) !== null ? { good: adminPortal.UsersChallenged, total: portalTotal, pct: pct(adminPortal.UsersChallenged, portalTotal) } : null
    if (portalFlow) inForce('IA.1-ADMINPORTAL', portalLabel, F.identity, flowCondition(portalFlow), [portalPolicy, portalSignIns || (portalUsers > 0 ? 'Every member sign-in to a Microsoft admin portal in the last 30 days reused a session that no policy checked.' : 'No member signed in to a Microsoft admin portal in the last 30 days.')].filter(Boolean).join(' '), portalRatio)
    else if (adminPortal && portalTotal > 0) control('IA.1-ADMINPORTAL', portalLabel, F.identity, adminPortal.UsersChallenged, portalTotal, `Members who signed in to a Microsoft admin portal in the last 30 days and satisfied multifactor authentication on at least one of those sign-ins.${portalSkipped}`)
    else if (!has('IA.1-ADMINPORTAL')) ungathered('IA.1-ADMINPORTAL', portalLabel, F.identity, reason('IA.1-ADMINPORTAL'), 'Members who signed in to a Microsoft admin portal in the last 30 days and satisfied multifactor authentication.')
    else notApplicable('IA.1-ADMINPORTAL', portalLabel, F.identity, `${portalUsers > 0 ? 'Every member sign-in to a Microsoft admin portal in the last 30 days reused a session that no policy checked' : 'No member signed in to a Microsoft admin portal in the last 30 days'} and no Conditional Access policy inventory, so there is no evidence either way.`)
    // Collector 1.13.0 counts a sign-in as MFA when an earlier sign-in in the same session carried direct MFA.
    // The client surfaces carry the inferred count in the split above, and the presenter notes explain it.
    const sessionLinkedText = sessionLinked > 0 ? `${plural(sessionLinked, 'member counts', 'members count')} as covered only by inference from an earlier MFA sign-in in the same session, not from MFA recorded on their own sign-ins.` : ''
    if (sessionLinkedText && !federated) presenter('MFA inferred from the session', sessionLinkedText)
    if (federated) {
      const provider = fedProviders
      const behavior = String(federation?.MfaBehavior ?? '')
      presenter('Federated sign-in and MFA', [
        `The tenant is federated${provider.length ? ` with ${list(provider)}` : ''}${fedDomains > 0 ? ` (${plural(fedDomains, 'domain', 'domains')})` : ', as the federated sign-ins in IA.1 show. The federated domains themselves could not be read'}.`,
        'Windows logon on hybrid-joined devices gets its token through WS-Trust, which cannot carry multifactor authentication, so the measure leaves it out.',
        'Most member sign-ins then reuse the device session and never return to the identity provider. Entra records whether a reused session carried MFA only when a Conditional Access policy with the Require multifactor authentication grant asks, so reused sessions are not evaluated rather than missing MFA.',
        unevaluated !== null && count(member?.UsersSignedIn) !== null ? `${fmt(unevaluated)} of ${fmt(member.UsersSignedIn)} members signed in only through such sessions in the last 30 days and are left out of the grade.` : '',
        sessionLinkedText,
        portalUnevaluated > 0 ? `At the admin portals, ${plural(portalUnevaluated, 'member was', 'members were')} left out the same way.` : '',
        count(member?.FederatedMfaAtLeastOnce) > 0 ? `${plural(member.FederatedMfaAtLeastOnce, 'member', 'members')} showed MFA asserted by the identity provider at least once, which confirms that it performs MFA and that Entra accepts the claim.` : '',
        count(member?.FederatedWithoutMfa) > 0 ? `${plural(member.FederatedWithoutMfa, 'member', 'members')} signed in through the identity provider without an MFA assertion. Whether that is acceptable depends on its sign-on policy.` : '',
        /rejectMfaByFederatedIdp/.test(behavior) ? 'Entra is set to reject MFA performed by the identity provider (rejectMfaByFederatedIdp), so a Require MFA policy would not count it.'
          : /enforceMfaByFederatedIdp/.test(behavior) ? 'When a policy requires MFA, Entra sends the member back to the identity provider for it (enforceMfaByFederatedIdp).'
          : /acceptIfMfaDoneByFederatedIdp/.test(behavior) ? 'Entra accepts MFA performed by the identity provider and prompts with its own MFA when the provider did none (acceptIfMfaDoneByFederatedIdp).' : '',
        'A report-only Conditional Access policy with the Require multifactor authentication grant for all members would record on every sign-in whether the session already carried MFA, without prompting anyone.'
      ].filter(Boolean).join(' '))
    }
    const deviceCode = one('IA.3-DEVICECODE')
    const deviceLabel = 'Device code flow sign-ins blocked'
    const deviceFlow = caFlow('Device code')
    const deviceAttempts = count(deviceCode?.Attempts) ?? 0, deviceSucceeded = count(deviceCode?.Succeeded) ?? 0
    const deviceActivity = deviceAttempts === 0 ? 'No device code sign-ins in the last 30 days.'
      : outsideScope(deviceFlow) && deviceSucceeded > 0 ? `${plural(deviceAttempts, 'device code attempt', 'device code attempts')} in the last 30 days. ${deviceSucceeded === deviceAttempts ? (deviceSucceeded === 1 ? 'It succeeded from an account' : `All ${fmt(deviceSucceeded)} succeeded from accounts`) : `The ${fmt(deviceSucceeded)} that succeeded came from accounts`} outside the policy scope.`
      : `${plural(deviceAttempts, 'device code attempt', 'device code attempts')} in the last 30 days, ${deviceSucceeded > 0 ? fmt(deviceSucceeded) : 'none'} succeeded.`
    const notItemized = [outsideScope(deviceFlow) && deviceSucceeded > 0 ? `${plural(deviceSucceeded, 'device code sign-in', 'device code sign-ins')}` : '', outsideScope(legacyFlow) && legacySucceeded > 0 ? `${plural(legacySucceeded, 'legacy protocol sign-in', 'legacy protocol sign-ins')}` : ''].filter(Boolean)
    if (notItemized.length) presenter('Conditional Access exceptions not itemized', `${list(notItemized)} succeeded while an enabled policy blocks the flow for all users, so the accounts are outside the policy scope, either excluded or signing in before the policy existed. This pack has no per-account sign-in detail. Recollect with collector 1.10.0 or later to have the SecOps worklist name the accounts and confirm each exclusion before presenting the controls.`)
    if (deviceFlow) {
      // The policy configuration decides the status. Sign-ins show whether any account got past it.
      inForce('IA.3-DEVICECODE', deviceLabel, F.identity, enforcedState(deviceFlow), [policyText(deviceFlow, 'device code flow'), deviceActivity, exceptionText(deviceFlow)].filter(Boolean).join(' '))
      if (enforcedState(deviceFlow) && bool(deviceFlow.DetailRead) && count(deviceFlow.SucceededUngoverned) > 0) presenter('Device code sign-ins outside the block policy', `${plural(deviceFlow.SucceededUngoverned, 'successful device code sign-in', 'successful device code sign-ins')} in the last 30 days were not evaluated by the enabled block policy. They most likely predate the policy. Confirm before presenting the control. The SecOps worklist names the accounts.`)
    } else if (!has('IA.3-DEVICECODE')) ungathered('IA.3-DEVICECODE', deviceLabel, F.identity, reason('IA.3-DEVICECODE'), 'Device code flow sign-ins blocked by Conditional Access.')
    else if (deviceAttempts === 0) notApplicable('IA.3-DEVICECODE', deviceLabel, F.identity, 'No device code sign-ins in the last 30 days and no Conditional Access policy inventory, so there is no evidence either way.')
    else if (deviceSucceeded > 0) {
      inForce('IA.3-DEVICECODE', deviceLabel, F.identity, false, deviceActivity)
      presenter('Device code exclusions not checked', `${plural(deviceSucceeded, 'device code sign-in', 'device code sign-ins')} succeeded, but this pack has no Conditional Access policy inventory, so accounts excluded from the block policy could not be told apart from a gap. Recollect with collector 1.10.0 or later and Policy.Read.All before presenting the control.`)
    } else if (count(deviceCode?.BlockedByCa) > 0) inForce('IA.3-DEVICECODE', deviceLabel, F.identity, true, `${plural(deviceAttempts, 'device code attempt', 'device code attempts')} in the last 30 days. Conditional Access stopped ${fmt(deviceCode.BlockedByCa)} and none succeeded.`)
    else notApplicable('IA.3-DEVICECODE', deviceLabel, F.identity, `${deviceActivity} ${noBlockEvidence}`)
    const ia6 = one('IA.6')
    const pimLabel = 'Privileged roles held through eligibility rather than standing assignment'
    const pimNote = 'Privileged Entra role assignments that are eligible through Privileged Identity Management, against eligible plus standing assignments.'
    const pimUnread = ia6 && String(ia6.PimRead ?? '') === 'NoPermission'
    const pim = pimUnread ? ungathered('IA.6', pimLabel, D.identity, 'PIM eligibility needs RoleManagement.Read.Directory, which the Graph token lacked', `${fmt(ia6.Standing)} active privileged assignments were read, but eligibility was not visible, so the share is not graded.`)
      : ia6 && count(ia6.Standing) !== null && count(ia6.Eligible) !== null ? control('IA.6', pimLabel, D.identity, ia6.Eligible, ia6.Standing + ia6.Eligible, pimNote)
      : (has('IA.6') ? null : control('IA.6', pimLabel, D.identity, null, null, pimNote))
    const risk = one('IA.11')
    inForce('IA.11', 'Identity Protection sign-in and user risk policies enforced', D.identity, has('IA.11') ? (risk ? bool(risk.InForce) : false) : null, risk && !bool(risk.InForce) ? `Sign-in risk policy for all users: ${bool(risk.SignInRiskAllUsers) ? 'yes' : 'no'}. User risk policy for all users: ${bool(risk.UserRiskAllUsers) ? 'yes' : 'no'}.` : 'An enabled Conditional Access policy with a sign-in risk condition and one with a user risk condition both include all users.')
    const consent = one('IA.13')
    const governedKnown = consent && String(consent.Governed ?? '').trim() !== ''
    inForce('IA.13', 'Application consent governed by administrative approval', D.identity, has('IA.13') ? (governedKnown ? bool(consent.Governed) : null) : null, consent ? (governedKnown ? `User consent: ${clean(consent.UserConsent)}. Admin consent request workflow ${bool(consent.AdminConsentWorkflow) ? 'on' : 'off'}.` : `User consent: ${clean(consent.UserConsent)}. The admin consent request workflow could not be read, so the control is not graded.`) : 'Users cannot consent, or only to low-risk permissions from verified publishers, and the admin consent request workflow is on.')
    const methods = rows('IA.2')
    const retiring = methods.find(r => /SMS or voice/i.test(r.Bucket))
    const resistant = methods.find(r => /Phishing-resistant/i.test(r.Bucket))
    const authenticator = methods.find(r => /Authenticator/i.test(r.Bucket))

    // Network virtual appliances (P0.6-APPLIANCES, collector 1.10.0) leave the VM measures they cannot take.
    const appliances = count(one('P0.6-APPLIANCES')?.Appliances) ?? 0
    const applianceText = appliances > 0 ? ` ${plural(appliances, 'network virtual appliance is', 'network virtual appliances are')} excluded because the vendor image cannot take this control.` : ''
    if (appliances > 0) note('Network virtual appliances', `P0.6-APPLIANCES: ${plural(appliances, 'machine runs', 'machines run')} a marketplace firewall or network appliance image. They are excluded from Trusted Launch, encryption at host, Azure Backup and the agent-based Defender for Cloud recommendations. The SecOps worklist names them.`)

    // Endpoint and workload. Every device measure reads Azure virtual machines only (Oct 14, 2026). Collector
    // 1.14.0 drops other endpoints at the source. Older packs carry Other device rows, which are left out here.
    // Network devices such as Palo Alto, Meraki, Fortinet and SonicWall firewalls stay out on older packs too.
    const vmRows = id => rows(id).filter(r => (r.Scope === undefined || r.Scope === 'Azure VM') && !NETWORK_DEVICE.test(String(r.OSPlatform ?? '')))
    const azureVms = vmRows('EW.1')
    const vmOnboarded = sum(azureVms, 'Onboarded'), vmEligible = sum(azureVms, 'CanBeOnboarded')
    // Why each Azure virtual machine is not reporting (EW.1-GAPS, collector 1.14.0), counted by reason. A machine
    // covered by a third-party endpoint detection product is protected. A reason that is not eligible, such as
    // a network virtual appliance or a deallocated machine, leaves the denominator. A machine Defender never
    // discovered joins it. Onboarded machines are already counted.
    const gaps = rows('EW.1-GAPS').filter(r => count(r.Devices) !== null)
    const gapEligible = r => bool(r.Eligible), gapCovered = r => bool(r.Covered)
    const coveredNotOnboarded = gaps.filter(r => gapCovered(r) && !/^Onboarded,/.test(String(r.Reason))).reduce((n, r) => n + Number(r.Devices) - (count(r.Onboarded) ?? 0), 0)
    const notSeenEligible = gaps.filter(gapEligible).reduce((n, r) => n + (count(r.NotSeen) ?? 0), 0)
    const ineligibleCounted = gaps.filter(r => !gapEligible(r)).reduce((n, r) => n + (count(r.CanBeOnboarded) ?? 0), 0)
    const edrGood = vmOnboarded !== null ? vmOnboarded + coveredNotOnboarded : null
    const edrTotal = vmOnboarded !== null && vmEligible !== null ? Math.max(edrGood, vmOnboarded + vmEligible + notSeenEligible - ineligibleCounted) : null
    const reasonText = r => {
      const n = Number(r.Devices), product = clean(r.Product)
      if (gapCovered(r) && !/^Onboarded,/.test(String(r.Reason))) return `${fmt(n)} ${n === 1 ? 'is' : 'are'} covered by ${product || 'a third-party endpoint detection product'}`
      return ({
        'Network virtual appliance, cannot run a sensor': `${fmt(n)} ${n === 1 ? 'is a network virtual appliance' : 'are network virtual appliances'} that cannot run a sensor`,
        'Operating system not supported by the sensor': `${fmt(n)} ${n === 1 ? 'runs' : 'run'} an operating system the sensor does not support`,
        'Deallocated or stopped at collection': `${fmt(n)} ${n === 1 ? 'was' : 'were'} deallocated or stopped at collection`,
        'Discovered only, insufficient information': `${fmt(n)} ${n === 1 ? 'was' : 'were'} discovered only, with too little information to onboard`,
        'Not discovered by Defender for Endpoint': `${fmt(n)} ${n === 1 ? 'has' : 'have'} never been discovered by Defender for Endpoint`,
        'Onboarded, sensor not active': `${fmt(n)} ${n === 1 ? 'is' : 'are'} onboarded with a sensor that is not active`,
        'Not onboarded, no endpoint detection found': `${fmt(n)} ${n === 1 ? 'is' : 'are'} not onboarded and ${n === 1 ? 'carries' : 'carry'} no endpoint detection product`
      })[String(r.Reason)] || `${fmt(n)}: ${clean(r.Reason).toLowerCase()}`
    }
    const gapCount = gaps.reduce((n, r) => n + Number(r.Devices), 0)
    const gapSensorOnly = gaps.every(r => /^Onboarded,/.test(String(r.Reason)))
    // An empty gap result reads as every machine reporting only when the onboarding and sensor figures agree.
    const reconciliation = has('EW.1-GAPS') && edrTotal !== null
      ? gapCount === 0 ? (edrGood === edrTotal && sum(azureVms, 'SensorActive') === vmOnboarded ? 'Every Azure virtual machine Defender for Endpoint has seen is onboarded with an active sensor.' : '')
        : `${plural(gapCount, 'Azure virtual machine is', 'Azure virtual machines are')} not reporting through an active Defender for Endpoint sensor. ${list(gaps.map(reasonText))}.`
      : ''
    // Azure Arc-enabled servers carry an Azure resource ID, so Defender for Endpoint counts them in the Azure scope
    // beside the native virtual machines. DR.2 lists them as hybrid compute machines.
    const arcServers = count(rows('DR.2').find(r => /hybridcompute\/machines/i.test(String(r.ResourceType ?? '')))?.Resources) ?? 0
    // The DR.2 count is inventory context only: the measure holds the Arc-enabled servers Defender for Endpoint saw.
    const arcText = arcServers > 0 ? ` Azure Arc-enabled servers carry an Azure resource ID, so those Defender for Endpoint has seen count here beside the native virtual machines. Resource Graph lists ${fmt(arcServers)} Arc-enabled servers at collection.` : ''
    const edrLabel = 'Azure virtual machines reporting to endpoint detection'
    const edrNote = `Azure virtual machines seen in the last 7 days that are onboarded to Defender for Endpoint or covered by another endpoint detection product, against the machines eligible for endpoint detection.${arcText} Workstations, laptops and other endpoints that are not Azure resources are not part of this measure.${reconciliation ? ' ' + reconciliation : ''}`
    const noAzureVms = has('EW.1') && !azureVms.length
    const edr = control('EW.1', edrLabel, F.endpoint, noAzureVms ? 0 : edrGood, noAzureVms ? 0 : edrTotal, edrNote)
    // Sensor health is read on onboarded Azure virtual machines only (Oct 12, 2026). The reconciliation explains
    // the difference between this figure and the onboarding figure.
    const sensors = control('EW.1', 'Endpoint sensors active on onboarded Azure virtual machines', F.detection, noAzureVms ? 0 : sum(azureVms, 'SensorActive'), noAzureVms ? 0 : vmOnboarded, `Active sensors among the Azure virtual machines onboarded to Defender for Endpoint, seen in the last 7 days.${arcText} Workstations and network devices such as firewalls are not part of this measure.${reconciliation ? ' ' + reconciliation : ''}`)
    if (has('EW.1-GAPS') && gapCount > 0 && !gapSensorOnly) note('Azure virtual machines not reporting to Defender for Endpoint', `EW.1-GAPS: ${reconciliation} The SecOps worklist names each machine with its evidence. A machine covered by a third-party product counts as protected in the onboarding figure, so confirm the product is licensed and reporting before the review.`)
    const edrInventory = one('EW.1-EDR')
    // EW.1-EDR inventories native virtual machines only, so the Arc share of any difference is named as unreconciled
    // rather than attributed to EW.1-GAPS, which explains the native machines.
    if (edrInventory && count(edrInventory.VMs) !== null && has('EW.1') && count(edrInventory.VMs) !== sum(rows('EW.1'), 'Devices')) note('Azure virtual machine inventory', `EW.1-EDR: ${fmt(edrInventory.VMs)} Azure virtual machines in Resource Graph against ${fmt(sum(rows('EW.1'), 'Devices'))} seen by Defender for Endpoint in the last 7 days. ${arcServers > 0 ? `Resource Graph also lists ${fmt(arcServers)} Azure Arc-enabled servers (DR.2), which carry an Azure resource ID and count in the Defender scope but are not in the EW.1-EDR inventory, so the Arc share of the difference is not reconciled machine by machine. ` : ''}${count(edrInventory.ThirdPartyEdr) > 0 ? `${plural(edrInventory.ThirdPartyEdr, 'machine carries', 'machines carry')} a third-party endpoint detection extension. ` : ''}EW.1-GAPS explains the native virtual machines machine by machine.`)
    const rtp = vmRows('EW.3').filter(r => /real-time protection/i.test(r.ConfigurationName) && count(r.Devices) !== null && count(r.Compliant) !== null)
    const antimalware = rtp.length ? control('EW.3', 'Real-time anti-malware protection enabled', F.endpoint, sum(rtp, 'Compliant'), sum(rtp, 'Devices'), 'Azure virtual machines compliant with the real-time protection configuration checks, all platforms.') : (has('EW.3') ? null : control('EW.3', 'Real-time anti-malware protection enabled', F.endpoint, null, null, 'Azure virtual machines compliant with the real-time protection configuration checks, all platforms.'))
    const va = vmRows('DR.5')
    const vaControl = control('DR.5', 'Vulnerability assessment running on onboarded Azure virtual machines', D.endpoint, sum(va, 'Assessed'), sum(va, 'Onboarded'), 'Onboarded Azure virtual machines with a vulnerability assessment result.')
    const ew7 = one('EW.7')
    const trusted = control('EW.7', 'Platform integrity through Trusted Launch', D.endpoint, ew7?.TrustedLaunchOrCvm, ew7?.VMs, `Azure virtual machines deployed with Trusted Launch or confidential computing.${applianceText}`)
    const encRows = rows('DP.4')
    const encryption = control('DP.4', 'Encryption at host on virtual machines', D.endpoint, sum(encRows, 'WithEncryptionAtHost'), sum(encRows, 'Resources'), `Virtual machine and scale set resources with the encryption at host setting. Disk encryption alternatives are reviewed separately.${applianceText}`)
    // Per-device secure configuration measures, Azure virtual machine rows only. EMPTY means no machine had an
    // applicable check, so the control is omitted.
    const deviceControl = (id, label, where, note) => {
      const r = vmRows(id).filter(x => count(x.Devices) !== null && count(x.Compliant) !== null)
      return r.length ? control(id, label, where, sum(r, 'Compliant'), sum(r, 'Devices'), note) : (has(id) ? null : control(id, label, where, null, null, note))
    }
    const tamper = deviceControl('EW.15', 'Tamper protection enforced on Azure virtual machines', F.endpoint, 'Onboarded Azure virtual machines seen in the last 30 days with tamper protection on.')
    const firewall = deviceControl('EW.16', 'Host firewall enforced through endpoint policy', F.endpoint, 'Onboarded Azure virtual machines with Microsoft Defender Firewall on for every profile.')
    const credential = deviceControl('EW.12', 'Credential protection enforced', D.endpoint, 'Onboarded Windows virtual machines with LSA protection on and WDigest credential caching off.')
    const rdp = deviceControl('EW.14', 'Remote Desktop hardened with TLS and Network Level Authentication', D.endpoint, 'Onboarded Windows virtual machines requiring TLS and Network Level Authentication for Remote Desktop.')
    const ew10 = one('EW.10')
    const cadenceText = count(p.PatchCadenceDays) ? ` of ${plural(p.PatchCadenceDays, 'day', 'days')}` : ''
    // Machines whose tags record patching as waived or client owned leave the measure (collector 1.14.0).
    const patchExcluded = count(one('EW.10-EXCLUDED')?.Machines)
    const patchExcludedText = patchExcluded > 0 ? ` ${plural(patchExcluded, 'machine is', 'machines are')} left out because a tag records patching as waived or client owned.` : ''
    // The row names both populations, assessed and excluded by tag. Machines Update Manager never assessed are not
    // counted by EW.10, so no third figure is printed. The tags are reviewed with the client, which the note says
    // without claiming any tag was confirmed.
    const patchReviewText = patchExcluded > 0 ? ' Atmosera reviews these tags with your team at each business review.' : ''
    const patch = ew10 && count(ew10.Machines) !== null ? control('EW.10', 'Operating system findings remediated within the patch cadence', F.endpoint, ew10.WithinCadence, ew10.Machines, `Machines assessed by Update Manager with no critical or security patch older than the agreed cadence${cadenceText}.${patchExcludedText}${patchReviewText}`, patchExcluded > 0 ? { excluded: patchExcluded, populations: `${fmt(ew10.Machines)} assessed · ${fmt(patchExcluded)} excluded by tag` } : {}) : (has('EW.10') ? null : control('EW.10', 'Operating system findings remediated within the patch cadence', F.endpoint, null, null, 'Machines assessed by Update Manager with no critical or security patch older than the agreed cadence.'))
    if (patchExcluded > 0) note('Patch measures', `EW.10-EXCLUDED: ${plural(patchExcluded, 'machine is', 'machines are')} left out of EW.6 and EW.10 because a tag records patching as waived or client owned. The SecOps worklist names them. Confirm that each tag is still intended.`)
    const appControl = one('EW.13')
    if (has('EW.13')) inForce('EW.13', 'Application allow-listing policy assigned', D.endpoint, appControl ? count(appControl.Assigned) > 0 : false, appControl && count(appControl.Policies) > 0 ? `${plural(appControl.Policies, 'App Control for Business policy', 'App Control for Business policies')}, ${fmt(appControl.Assigned)} assigned.` : 'No App Control for Business policy is defined in Intune.')
    else ungathered('EW.13', 'Application allow-listing policy assigned', D.endpoint, reason('EW.13'), 'An App Control for Business policy assigned in Intune.')

    // Network and boundary.
    const nb4 = one('NB.4'), nb1 = one('NB.1'), nb5 = one('NB.5'), nb6 = one('NB.6'), dp1 = one('DP.1')
    const https = control('NB.4', 'Encryption in transit enforced on published web apps', F.network, nb4?.HttpsOnly, nb4?.Sites, 'Web and function apps with the HTTPS-only setting.')
    const segmentation = control('NB.1', 'Workload subnets protected by segmentation', D.network, nb1?.Segmented, nb1?.WorkloadSubnets, 'Workload subnets with a network security group or a route through the firewall.')
    const sqlTls = control('NB.6', 'Transport encryption enforced on Azure SQL', F.network, nb6?.MinTls12, nb6?.Servers, 'Azure SQL servers requiring TLS 1.2 or newer.')
    const appTls = control('NB.5', 'App Service minimum TLS 1.2', F.network, nb5?.MinTls12, nb5?.Configs, 'App Service configurations requiring TLS 1.2 or newer.')
    const publicOff = control('DP.1', 'Storage accounts closed to public networks', D.network, dp1?.PublicNetworkOff, dp1?.Accounts, 'Storage accounts with public network access disabled.')
    const anon = control('DP.1', 'Anonymous blob access disabled', F.network, dp1?.AnonymousBlobOff, dp1?.Accounts, 'Storage accounts with account-level anonymous access disabled.')
    // Container level (DP.1-CONTAINERS, collector 1.11.0): the container's own access level, read in every account,
    // so a container stays closed even if the account-level setting is relaxed later.
    const dp1c = one('DP.1-CONTAINERS')
    const containerLabel = 'Blob containers closed to anonymous access'
    const containerNote = 'Blob containers set to private at the container level, read in every storage account, so they stay closed even if the account-level setting is relaxed.'
    const containers = dp1c && count(dp1c.Containers) !== null ? control('DP.1-CONTAINERS', containerLabel, D.network, dp1c.PrivateContainers, dp1c.Containers, containerNote) : (has('DP.1-CONTAINERS') ? null : control('DP.1-CONTAINERS', containerLabel, D.network, null, null, containerNote))
    if (dp1c && count(dp1c.ExposedContainers) > 0) presenter('Blob containers readable anonymously', `${plural(dp1c.ExposedContainers, 'blob container is', 'blob containers are')} readable anonymously today in ${plural(dp1c.AccountsExposed, 'storage account', 'storage accounts')}, because the container is set to public and the account setting allows it. The SecOps worklist names them. Confirm whether each one serves public content by design before presenting.`)
    if (dp1c && count(dp1c.AccountsUnread) > 0) note('Blob containers not read', `DP.1-CONTAINERS: the containers of ${plural(dp1c.AccountsUnread, 'storage account', 'storage accounts')} could not be listed and are not counted. The collector detail names the error.`)
    const netProtect = deviceControl('NB.8', 'Network protection in block mode on Azure virtual machines', F.network, 'Onboarded Windows virtual machines in Azure with network protection in block mode, which covers egress and DNS monitoring. The Sentinel tunneling and beaconing rules are confirmed in the review worksheet.')
    const ldap = deviceControl('NB.10', 'Directory traffic signed and channel-bound', D.network, 'Domain controllers in Azure requiring LDAP server signing and channel binding.')
    const ntlm = deviceControl('NB.11', 'NTLMv2 enforced with LM and NTLM refused', D.network, 'Onboarded Windows virtual machines in Azure sending NTLMv2 responses only.')
    const boundary = windowValid ? rows('OUT.6') : []
    const boundaryCount = boundary.length ? sum(boundary, 'Alerts') : (has('OUT.6') ? 0 : null)

    // Data protection.
    const dp2 = one('DP.2'), dp3 = rows('DP.3')
    const transfer = control('DP.1', 'Secure transfer required on storage accounts', F.data, dp1?.SecureTransfer, dp1?.Accounts, 'Storage accounts configured to require secure transfer.')
    const tls = control('DP.1', 'Storage minimum TLS 1.2', F.data, dp1?.MinTls12, dp1?.Accounts, 'Storage accounts requiring TLS 1.2 or newer.')
    const softDelete = control('DP.2', 'Key Vault soft delete', F.data, dp2?.SoftDelete, dp2?.Vaults, 'Vaults able to recover deleted secrets, keys and certificates.')
    const purge = control('DP.2', 'Key Vault purge protection', F.data, dp2?.PurgeProtection, dp2?.Vaults, 'Vaults protected against permanent deletion during the retention period.')
    const rbac = control('DP.2', 'Key Vault access governed by role-based access control', D.data, dp2?.RbacAuth, dp2?.Vaults, 'Vaults using the Azure RBAC permission model.')
    const disks = dp3.filter(r => count(r.Disks) !== null)
    const diskTotal = sum(disks, 'Disks'), diskEncrypted = disks.length ? disks.filter(r => /EncryptionAtRest|Encrypted|Customer|Platform/i.test(String(r.EncryptionType))).reduce((n, r) => n + Number(r.Disks), 0) : null
    control('DP.3', 'Managed disks encrypted at rest', F.data, diskEncrypted, diskTotal, 'Managed disks encrypted with platform or customer managed keys.')
    const vmTotal = sum(encRows, 'Resources'), noBackup = count(one('DP.5b')?.VmsWithoutBackup)
    const backup = control('DP.5b', 'Azure Backup protecting virtual machines', D.data, vmTotal !== null && noBackup !== null ? Math.max(0, vmTotal - noBackup) : null, vmTotal, `Virtual machines with a protected backup item. Pooled session hosts may be excluded by agreement.${applianceText}`)
    const safeLinks = rows('IA.9-SAFELINKS'), safeAttach = rows('IA.9-SAFEATTACH')
    inForce('IA.9-SAFELINKS', 'Safe Links scanning on mail, Teams and Office', F.data, has('IA.9-SAFELINKS') ? safeLinks.some(r => [r.EnableSafeLinksForEmail, r.EnableSafeLinksForTeams, r.EnableSafeLinksForOffice].every(v => v === true || String(v).toLowerCase() === 'true')) : null, 'At least one Safe Links policy covers mail, Teams and Office.')
    inForce('IA.9-SAFEATTACH', 'Safe Attachments blocking malicious files', F.data, has('IA.9-SAFEATTACH') ? safeAttach.some(r => (r.Enable === true || String(r.Enable).toLowerCase() === 'true') && /block|dynamic|replace/i.test(String(r.Action))) : null, 'At least one enabled Safe Attachments policy blocks or replaces malicious attachments.')
    const zap = rows('DP.7').filter(r => /ZAP|Remediation/i.test(String(r.ActionType)))
    const mailRemoved = zap.length ? sum(zap, 'Succeeded') : null
    m.mailRemoved = mailRemoved
    if (zap.length) inForce('DP.7', 'Malicious mail removed after delivery', F.data, mailRemoved > 0, `${fmt(mailRemoved)} post-delivery removals succeeded in the last 30 days.`)
    else if (!has('DP.7')) ungathered('DP.7', 'Malicious mail removed after delivery', F.data, reason('DP.7'), 'Post-delivery removals of malicious mail in the last 30 days.')
    const zapRows = rows('DP.7-ZAP')
    if (has('DP.7-ZAP')) inForce('DP.7-ZAP', 'Zero-hour auto purge enabled for malware, spam and phishing', F.data, zapRows.length > 0 && zapRows.every(r => /malware/i.test(String(r.Kind)) ? bool(r.ZapEnabled) : (bool(r.PhishZapEnabled) && bool(r.SpamZapEnabled))), 'Every malware and content filter policy keeps zero-hour auto purge on.')
    else ungathered('DP.7-ZAP', 'Zero-hour auto purge enabled for malware, spam and phishing', F.data, reason('DP.7-ZAP'), 'Every malware and content filter policy keeps zero-hour auto purge on.')
    const sharing = one('DP.8')
    if (has('DP.8')) inForce('DP.8', 'Collaboration sharing boundaries defined', D.data, sharing ? !/externalUserAndGuestSharing/i.test(String(sharing.SharingCapability)) : false, sharing ? `Tenant sharing level ${clean(sharing.SharingCapability)}${/allowList/i.test(String(sharing.DomainRestrictionMode)) ? ' with an allowed domain list' : ''}.` : 'Tenant sharing settings were not returned.')
    else ungathered('DP.8', 'Collaboration sharing boundaries defined', D.data, reason('DP.8'), 'Tenant sharing level below anyone links, with domain restrictions where agreed.')
    const intuneEncrypted = rows('DP.10').filter(r => /^(Windows|macOS)$/i.test(String(r.OperatingSystem)) && count(r.Devices) !== null && count(r.Encrypted) !== null)
    const bitlocker = rows('EW.3').filter(r => /BitLocker-supported drives/i.test(String(r.ConfigurationName)) && count(r.Devices) !== null && count(r.Compliant) !== null)
    if (intuneEncrypted.length) control('DP.10', 'Endpoint disk encryption enforced on managed devices', D.data, sum(intuneEncrypted, 'Encrypted'), sum(intuneEncrypted, 'Devices'), 'Intune-managed Windows and macOS devices reported as encrypted.')
    else if (bitlocker.length) control('DP.10', 'Endpoint disk encryption enforced on managed devices', D.data, sum(bitlocker, 'Compliant'), sum(bitlocker, 'Devices'), 'Onboarded Windows devices passing the BitLocker drive encryption check. Intune encryption state was not available, so the endpoint configuration check stands in.', { source: source('EW.3') })
    else if (!has('DP.10')) ungathered('DP.10', 'Endpoint disk encryption enforced on managed devices', D.data, reason('DP.10'), 'Managed Windows and macOS devices reported as encrypted.')

    // Detection and response.
    // The resource types outside Standard plan coverage, named on the control (Oct 14, 2026). The plan code is
    // written as the resource type a reader knows, and the counts are summed per plan.
    const PLAN_NAMES = { AI: 'AI services', KeyVaults: 'Key Vault', StorageAccounts: 'storage account', VirtualMachines: 'virtual machine', AppServices: 'App Service', SqlServers: 'SQL server', CosmosDbs: 'Cosmos DB', ContainerRegistry: 'container registry', KubernetesService: 'Kubernetes', Containers: 'container', OpenSourceRelationalDatabases: 'open-source database', SqlServerVirtualMachines: 'SQL on virtual machine', Api: 'API Management', Dns: 'DNS', Arm: 'Resource Manager' }
    const planGaps = [...rows('DR.2').filter(r => count(r.Resources) !== null && count(r.Covered) !== null && r.Resources > r.Covered).reduce((acc, r) => { const k = clean(r.Plan) || 'other'; return acc.set(k, (acc.get(k) || 0) + (r.Resources - r.Covered)) }, new Map())]
      .sort((a, b) => b[1] - a[1]).map(([planCode, n]) => ({ n, name: PLAN_NAMES[planCode] || clean(planCode).replace(/([a-z])([A-Z])/g, '$1 $2').toLowerCase() }))
    const planGapText = planGaps.length ? ` Not covered: ${list(planGaps.map(g => `${fmt(g.n)} ${g.name} ${g.n === 1 ? 'resource' : 'resources'}`))}.` : ''
    const planGapShort = planGaps.length ? `${list(planGaps.map(g => `${fmt(g.n)} ${g.name}`))} not covered` : ''
    const plan = control('DR.2', 'Cloud workload protection across the resource estate', F.detection, sum(rows('DR.2'), 'Covered'), sum(rows('DR.2'), 'Resources'), `Eligible resources on a Standard Defender for Cloud plan, read from the subscription plan configuration.${planGapText}`, { estimate: true, ...(planGapShort ? { gap: planGapShort } : {}) })
    const aiRow = rows('DR.2').find(r => r.Plan === 'AI')
    // DR.6 counts assessment entries and duplicated DR.13, so it no longer has a control row (Oct 12, 2026).
    // Diagnostic logging is graded per resource by DR.13 in defense in depth. DR.6 remains a fallback for the backlog.
    const logging = rows('DR.6').filter(r => count(r.Healthy) !== null && count(r.Unhealthy) !== null)
    // Tiers (Oct 16, 2026): the Atmosera standard analytics rule set (DR.9) and threat intelligence ingestion (DR.7)
    // are switched on at build, so they are foundational. Domain controller telemetry (DR.4) and Defender for Identity
    // sensors (DR.11) need Defender for Identity licensing and a sensor on each domain controller from the client, and
    // do not apply to cloud-only tenants, so they are defense in depth.
    // DR.9 is a presence check (Oct 16, 2026): In force when every Sentinel workspace in scope has at least one enabled
    // analytics rule. The evidence cannot tell Atmosera's standard rules from others, since they carry no naming
    // convention, so the grade never claims the standard set. The enabled of total count is context only: disabled
    // noisy rules are tuning, never a foundational gap. The collector writes one summary scope per workspace that
    // holds rules, so a workspace with none has no scope. That reads as zero only when every workspace was read.
    const ruleMetric = (scope, metric) => count(rows('DR.9').find(r => String(r.Scope).toLowerCase() === scope.toLowerCase() && String(r.Metric).toLowerCase() === metric.toLowerCase())?.Value)
    const ruleTotal = ruleMetric('All workspaces', 'Total rules'), ruleEnabled = ruleMetric('All workspaces', 'Enabled rules')
    const ruleLabel = 'Analytics rules enabled in every Sentinel workspace'
    const ruleNote = 'Sentinel workspaces with at least one enabled analytics rule, of the workspaces in scope. It does not identify which rules are Atmosera\'s standard set.'
    const ruleScopes = [...new Set(rows('DR.9').map(r => clean(r.Scope)).filter(x => x && !/^All workspaces$/i.test(x)))]
    const ruleWorkspaces = m.workspaces.map(w => clean(w.Name)).filter(Boolean)
    // A pack with one workspace and only the All workspaces scope reads that scope as the workspace.
    const inScope = ruleWorkspaces.length ? ruleWorkspaces : ruleScopes.length ? ruleScopes : ruleTotal !== null ? ['All workspaces'] : []
    const singleScope = inScope.length === 1 && !ruleScopes.length
    // Several workspaces with only the All workspaces scope (no per-workspace breakdown) cannot say which one holds the rules.
    const noBreakdown = inScope.length > 1 && !ruleScopes.length
    const wsEnabled = w => { if (noBreakdown) return ruleTotal === 0 && state('DR.9') === 'OK' ? 0 : undefined; const v = ruleMetric(singleScope ? 'All workspaces' : w, 'Enabled rules'); return v !== null ? v : ruleScopes.some(x => x.toLowerCase() === w.toLowerCase()) ? null : state('DR.9') === 'OK' ? 0 : undefined }
    const ruleReadings = inScope.map(wsEnabled)
    const ruleContext = ruleTotal !== null && ruleEnabled !== null ? ` ${fmt(ruleEnabled)} of ${plural(ruleTotal, 'analytics rule', 'analytics rules')} enabled across ${plural(inScope.length, 'workspace', 'workspaces')}, as context: disabled rules do not move the grade.` : ''
    const emptyWorkspaces = ruleReadings.filter(v => v === 0).length
    let ruleControl
    if (!has('DR.9') || ruleTotal === null || !inScope.length) ruleControl = ungathered('DR.9', ruleLabel, F.detection, has('DR.9') ? 'the result does not contain a valid reading' : reason('DR.9'), ruleNote)
    else if (emptyWorkspaces > 0) {
      ruleControl = inForce('DR.9', ruleLabel, F.detection, false, `${plural(emptyWorkspaces, 'Sentinel workspace has', 'Sentinel workspaces have')} no enabled analytics rule. ${ruleNote}${ruleContext}`)
      ruleControl.gap = inScope.length === 1 ? 'no enabled rule in the workspace' : `${fmt(emptyWorkspaces)} of ${fmt(inScope.length)} workspaces without an enabled rule`
    }
    else if (partial('DR.9') || ruleReadings.some(v => v === undefined || v === null)) ruleControl = ungathered('DR.9', ruleLabel, F.detection, 'a Sentinel workspace could not be read, so an enabled rule in every workspace cannot be confirmed', ruleNote)
    else ruleControl = inForce('DR.9', ruleLabel, F.detection, true, `${ruleNote}${ruleContext}`)
    const ti = one('DR.7')
    inForce('DR.7', 'Threat intelligence indicators ingested tenant-wide', F.detection, has('DR.7') ? count(ti?.Indicators) > 0 : null, ti ? `${fmt(ti.Indicators)} indicators available for matching.` : has('DR.7') ? 'No threat intelligence table recorded.' : 'Threat intelligence indicators available for matching in the workspace.')
    const dc = rows('DR.4')
    if (has('DR.4')) inForce('DR.4', 'Domain controller telemetry collected continuously', D.detection, dc.length > 0 && sum(dc, 'Events') > 0, dc.length ? `${plural(dc.length, 'domain controller', 'domain controllers')} reporting.` : 'No domain controller events recorded.')
    else ungathered('DR.4', 'Domain controller telemetry collected continuously', D.detection, reason('DR.4'), 'Domain controller security events arriving in the workspace.')
    const triage = one('DR.10')
    const dispositions = triage && count(triage.Closed) !== null ? control('DR.10', 'Alerts closed with a documented disposition', F.detection, triage.Documented, triage.Closed, 'Alerts closed in the last 30 days that carry a classification and a closing comment.') : null
    if (!dispositions && !has('DR.10')) ungathered('DR.10', 'Alerts closed with a documented disposition', F.detection, reason('DR.10'), 'Alerts closed in the last 30 days that carry a classification and a closing comment.')
    const mdiSensors = one('DR.11')
    const mdiLabel = 'Defender for Identity sensors healthy on domain controllers'
    if (mdiSensors && count(mdiSensors.Sensors) !== null) control('DR.11', mdiLabel, D.detection, mdiSensors.Healthy, mdiSensors.Sensors, 'Sensors reporting healthy, of sensors registered. A domain controller with no sensor is found by comparing with the directory.')
    // The service answered that the tenant is not onboarded to Defender for Identity (manifest NotOnboarded). That
    // is evidence the control is not in place, not a read the token was refused, so it reads Not in force and
    // needs a license and sensors rather than read access (Oct 14, 2026). Only where the collection shows a
    // directory estate: domain controllers in Azure (NB.10) or domain controller events (DR.4). A cloud-only
    // tenant has nowhere to put a sensor, so there the control does not apply.
    else if (!has('DR.11') && bool(index.get('DR.11')?.NotOnboarded)) {
      // Domain controllers are positive evidence only: NB.10 reads the ones in Azure and DR.4 reads telemetry that
      // Defender for Identity itself supplies, so neither can prove that a tenant has none. Without that evidence
      // the control stays ungathered rather than reading as a gap or as not applicable.
      const directoryEstate = rows('NB.10').some(r => count(r.Devices) > 0) || rows('DR.4').some(r => count(r.Events) > 0)
      if (directoryEstate) inForce('DR.11', mdiLabel, D.detection, false, 'The tenant is not onboarded to Microsoft Defender for Identity, so no sensor reports from a domain controller.')
      else ungathered('DR.11', mdiLabel, D.detection, 'the tenant is not onboarded to Defender for Identity and the collection holds no evidence of domain controllers (NB.10 reads Azure virtual machines only, DR.4 needs Defender for Identity telemetry)', 'Sensors reporting healthy, of sensors registered. Whether the tenant has domain controllers could not be established in this collection.')
    }
    else if (!has('DR.11')) ungathered('DR.11', mdiLabel, D.detection, reason('DR.11'), 'Sensors reporting healthy, of sensors registered.')
    const logPerResource = one('DR.13')
    if (logPerResource && count(logPerResource.Resources) !== null) control('DR.13', 'Diagnostic logging enabled on all platform resources', D.detection, logPerResource.AllHealthy, logPerResource.Resources, 'Resources with every diagnostic and audit logging assessment healthy, of resources with at least one such assessment.')
    else if (!has('DR.13')) ungathered('DR.13', 'Diagnostic logging enabled on all platform resources', D.detection, reason('DR.13'), 'Resources with every diagnostic and audit logging assessment healthy.')
    const initiative = rows('DR.6-INITIATIVE').filter(r => count(r.Resources) !== null && count(r.Compliant) !== null)
    if (initiative.length) control('DR.6-INITIATIVE', 'Audit logging initiative compliant across its resources', F.detection, sum(initiative, 'Compliant'), sum(initiative, 'Resources'), 'Resources compliant with the ATMO-MXDR diagnostic logging initiative, summed across its policies.')
    else if (has('DR.6-INITIATIVE')) note('Audit logging initiative', 'DR.6-INITIATIVE: the ATMO-MXDR diagnostic logging initiative is not assigned in these subscriptions, so the control is omitted from the client page.')
    else ungathered('DR.6-INITIATIVE', 'Audit logging initiative compliant across its resources', F.detection, reason('DR.6-INITIATIVE'), 'Resources compliant with the ATMO-MXDR diagnostic logging initiative.')
    const groups = one('DR.12')
    if (groups && count(groups.Devices) !== null) note('Attack disruption readiness', `DR.12: ${fmt(groups.Devices)} onboarded Azure virtual machines across ${plural(groups.Groups, 'device group', 'device groups')}. Confirm the automation level of each group in the Defender portal before grading attack disruption.`)
    const mgmt = one('IA.14')
    if (mgmt && count(mgmt.Users) !== null) note('Azure management plane access', `IA.14: ${plural(mgmt.Users, 'user', 'users')} signed in to Azure management in the last 30 days. Compare with the privileged role holders in the worksheet before grading the management plane control.`)
    const telemetry = rows('DR.3').length

    // Backlog counts for the hardening tier.
    const critical = vmRows('BKL.1').filter(r => /Critical/i.test(r.VulnerabilitySeverityLevel))
    const criticalCves = has('BKL.1') ? (sum(critical, 'ExploitableCves') ?? 0) : null
    const exploitable = has('BKL.1') ? (sum(vmRows('BKL.1'), 'ExploitableCves') ?? 0) : null
    m.criticalCves = criticalCves
    // A hardening count can carry the population it is counted against (of), so the executive summary
    // reads "14 of 194" beside a control that reads "180 of 194" and the two figures reconcile at a glance.
    const hardening = []
    const harden = (label, value, id, rank, of = null) => { if (count(value) !== null && value > 0) hardening.push({ label: clean(label), value, id, rank, of: count(of) !== null && of >= value ? of : null }) }
    const hardenText = h => h.of !== null ? `${fmt(h.value)} of ${fmt(h.of)}` : fmt(h.value)
    harden('Critical exploitable findings open', criticalCves, 'BKL.1', 1)
    harden('Virtual machines pending host encryption', encryption.total !== null ? encryption.total - encryption.good : null, 'DP.4', 8)
    harden('Users on a retiring MFA method', count(retiring?.DistinctUsers), 'IA.2', 3)
    const logPerResourceValid = logPerResource && count(logPerResource.Resources) !== null && count(logPerResource.AllHealthy) !== null
    const logGap = logPerResourceValid ? { n: logPerResource.Resources - logPerResource.AllHealthy, id: 'DR.13', text: n => `${fmt(n)} platform resources are missing at least one diagnostic or audit log setting.` }
      : logging.length ? { n: sum(logging, 'Unhealthy'), id: 'DR.6', text: n => `${fmt(n)} assessment entries report platform resources without diagnostic or audit logging.` } : null
    harden('Resources without diagnostic logging', logGap ? logGap.n : null, logGap ? logGap.id : 'DR.13', 7)
    harden('AI service resources without workload protection', aiRow ? count(aiRow.Resources) - count(aiRow.Covered) : null, 'DR.2', 6)
    harden('Workload subnets without segmentation', segmentation.total !== null ? segmentation.total - segmentation.good : null, 'NB.1', 12)
    harden('Key Vaults without purge protection', purge.total !== null ? purge.total - purge.good : null, 'DP.2', 11)
    harden('Storage accounts open to public networks', publicOff.total !== null ? publicOff.total - publicOff.good : null, 'DP.1', 10)
    harden('Virtual machines without Azure Backup', backup.total !== null ? backup.total - backup.good : null, 'DP.5b', 9)
    harden('Azure virtual machines pending endpoint onboarding', edr.total !== null ? edr.total - edr.good : null, 'EW.1', 4)
    // Counted against the same members as the Multifactor authentication required at sign-in control, so the
    // executive summary figure and the control figure share their denominator.
    const mfaPopulation = mfaRatio && !isInForce(mfa) ? mfaRatio : mfa.total !== null && !mfa.boolean ? { good: mfa.good, total: mfa.total } : null
    // In a federated tenant the count is among the members evaluated, not every member who signed in (issue #21).
    harden(unevaluated !== null ? 'Evaluated members without MFA, last 30 days' : 'Members who signed in without MFA, last 30 days', mfaPopulation ? mfaPopulation.total - mfaPopulation.good : null, 'IA.1', 2, mfaPopulation ? mfaPopulation.total : null)
    harden('Open alerts referred for client action', m.alerts?.open ?? null, 'OUT.1', 99)
    m.hardening = hardening.sort((a, b) => a.rank - b.rank)

    // Priorities, ranked by a fixed sequence. Open alerts are never a priority.
    const priority = (rank, title, evidence, action, success, id) => m.priorities.push({ rank, title: clean(title), evidence: clean(evidence), action: clean(action), success: clean(success), id, source: source(id) })
    if (criticalCves > 0) priority(1, 'Critical vulnerability remediation', `${fmt(criticalCves)} critical exploitable findings are open across operating system and application software. The same finding can appear on several device groups.`, 'Validate the affected workloads and business impact, then schedule remediation or compensating controls with the owners inside the regular patch cadence.', 'Critical exploitable findings resolved or covered by an approved treatment plan.', 'BKL.1')
    // In a federated tenant the identity provider's own sign-on rules and federatedIdpMfaBehavior decide what a Require
    // MFA policy enforces, so they are reviewed first, as an explicit step (issue #21).
    const fedReview = unevaluated !== null ? `Review the authentication policy of the federated identity provider${fedProviders.length ? ` (${list(fedProviders)})` : ''} and the federatedIdpMfaBehavior setting of each federated domain before extending Conditional Access, since enforcement depends on how federation and existing sessions are handled. ` : ''
    if (mfa.boolean && !isInForce(mfa)) priority(2, 'Multifactor authentication for every user', `${mfaPolicy}${mfaRatio ? ` ${fmt(mfaRatio.total - mfaRatio.good)} of ${fmt(mfaRatio.total)} members${unevaluated !== null ? ' whose sign-ins could be evaluated' : ''} showed no multifactor authentication in the last 30 days.` : ''}`, `${fedReview}${fedReview ? 'Then extend' : 'Extend'} the Conditional Access policy to all users and every application, confirm exclusions and service accounts, pilot in report-only mode, then move to enforcement in waves.`, 'An enabled Conditional Access policy requires multifactor authentication for all users on every application, with documented exceptions.', 'IA.1')
    else if (!mfa.boolean && mfa.pct !== null && mfa.pct < E_THRESHOLD) {
      if (unevaluated !== null) priority(2, 'Multifactor authentication for every user', `${fmt(mfa.total - mfa.good)} of ${fmt(mfa.total)} members whose sign-ins could be evaluated showed no multifactor authentication in the last 30 days. Members whose only sign-ins reused a device session that no policy checked are not part of this figure.`, `${fedReview}Then deploy a report-only Conditional Access policy requiring multifactor authentication for all members to measure session coverage, and move to enforcement in waves.`, 'Every member sign-in evaluated by policy and covered by multifactor authentication, with documented exceptions.', 'IA.1')
      else priority(2, 'Multifactor authentication for every user', `${fmt(mfa.total - mfa.good)} of ${fmt(mfa.total)} active members signed in without a recorded multifactor requirement in the last 30 days.`, 'Confirm exclusions and service accounts, pilot the Conditional Access change in report-only mode, then move to enforcement in waves.', 'Every intended user covered by validated policy, with documented exceptions.', 'IA.1')
    }
    // IA.2 counts methods used, not registered, so use alone never reads as sole reliance. PhoneOnly (IA.5,
    // added Oct 16, 2026) counts members whose only registered MFA method is a phone, as an aggregate across members.
    // A pack without it, or a partial read, leaves reliance not yet evaluated (Oct 16, 2026).
    const phoneOnly = state('IA.5') === 'OK' ? count(one('IA.5')?.PhoneOnly) : null
    const reliance = phoneOnly === null ? 'Whether these users hold another registered MFA method is not yet evaluated.'
      : phoneOnly === 0 ? 'The registration read finds no member whose only registered MFA method is text message or voice.'
      : `The registration read finds ${plural(phoneOnly, 'member', 'members')} whose only registered MFA method is text message or voice.`
    if (count(retiring?.DistinctUsers) > 0) priority(3, 'MFA method update', `${plural(retiring.DistinctUsers, 'user', 'users')} signed in with text message or voice in the last 30 days. Microsoft retires these methods on ${RETIREMENT.text}. ${reliance}`, 'Notify the affected users, register each one on a passkey (in Microsoft Authenticator, a Microsoft Entra passkey on Windows or a FIDO2 security key) or on Windows Hello for Business in guided waves, then remove text message and voice from the allowed methods under change control. Microsoft Authenticator push is outside this retirement and stays supported. A telephony provider from Microsoft Security Store is kept only for a documented regulatory or operational need.', MFA_OUTCOME, 'IA.2')
    if (edr.pct !== null && edr.pct < E_THRESHOLD) priority(4, 'Endpoint coverage', `${fmt(edr.total - edr.good)} of ${fmt(edr.total)} eligible Azure virtual machines are not yet reporting to endpoint detection.${reconciliation ? ' ' + reconciliation : ''}`, 'Confirm ownership and operating state, complete onboarding and verify sensor health.', 'Every eligible Azure virtual machine reports through an active sensor.', 'EW.1')
    if (antimalware && antimalware.pct !== null && antimalware.pct < E_THRESHOLD) priority(5, 'Anti-malware configuration', `${fmt(antimalware.total - antimalware.good)} of ${fmt(antimalware.total)} Azure virtual machines do not meet the real-time protection configuration checks.`, 'Apply the endpoint security baseline to the affected platforms and verify through the configuration assessment.', 'Real-time protection enforced on every onboarded Azure virtual machine.', 'EW.3')
    if (plan.pct !== null && plan.pct < E_THRESHOLD || (aiRow && count(aiRow.Resources) - count(aiRow.Covered) > 0)) priority(6, 'Workload protection scope', `${plan.total !== null && plan.total - plan.good > 0 ? `${plural(plan.total - plan.good, 'eligible resource is', 'eligible resources are')} outside Standard plan coverage.` : ''}${aiRow && count(aiRow.Resources) - count(aiRow.Covered) > 0 ? ` ${plural(count(aiRow.Resources) - count(aiRow.Covered), 'AI service resource is', 'AI service resources are')} not yet covered.` : ''}`, 'Validate resource-level coverage in Defender for Cloud and agree the intended protection scope, including AI services.', 'Every agreed resource has workload protection or a documented exception.', 'DR.2')
    if (logGap && logGap.n > 0) priority(7, 'Diagnostic logging coverage', logGap.text(logGap.n), 'Prioritize the workloads that matter most, then enable the required logs with the agreed destination and retention.', 'The agreed telemetry reaches the workspace and supports the intended detections.', logGap.id)
    if (encryption.pct !== null && encryption.pct < E_THRESHOLD) priority(8, 'Encryption at host', `${fmt(encryption.total - encryption.good)} of ${fmt(encryption.total)} virtual machine resources do not have encryption at host enabled.`, 'Confirm existing disk encryption, workload support and maintenance windows, then enable in planned batches.', 'Each workload has a confirmed encryption approach or an approved exception.', 'DP.4')
    if (backup.pct !== null && backup.pct < E_THRESHOLD) priority(9, 'Backup coverage', `${fmt(backup.total - backup.good)} of ${fmt(backup.total)} virtual machines have no protected backup item.`, 'Confirm which machines are persistent, exclude pooled session hosts by agreement, then extend the backup policy.', 'Every persistent virtual machine carries a backup policy.', 'DP.5b')
    if ((transfer.pct !== null && transfer.pct < E_THRESHOLD) || (tls.pct !== null && tls.pct < E_THRESHOLD) || (publicOff.pct !== null && publicOff.pct < E_THRESHOLD) || (appTls.pct !== null && appTls.pct < E_THRESHOLD)) priority(10, 'Transport encryption and exposure', `${transfer.pct !== null && transfer.pct < E_THRESHOLD ? `${fmt(transfer.total - transfer.good)} storage accounts allow insecure transfer. ` : ''}${tls.pct !== null && tls.pct < E_THRESHOLD ? `${fmt(tls.total - tls.good)} storage accounts do not require TLS 1.2. ` : ''}${publicOff.pct !== null && publicOff.pct < E_THRESHOLD ? `${fmt(publicOff.total - publicOff.good)} storage accounts remain reachable from public networks. ` : ''}${appTls.pct !== null && appTls.pct < E_THRESHOLD ? `${fmt(appTls.total - appTls.good)} App Service configurations accept TLS below 1.2.` : ''}`, 'Check application compatibility, then stage secure transfer, TLS 1.2 and private connectivity in agreed batches.', 'The agreed storage and App Service scope requires secure transfer, TLS 1.2 and private access.', 'DP.1')
    if ((purge.pct !== null && purge.pct < E_THRESHOLD) || (rbac.pct !== null && rbac.pct < E_THRESHOLD)) priority(11, 'Key protection', `${purge.pct !== null && purge.pct < E_THRESHOLD ? `${fmt(purge.total - purge.good)} of ${fmt(purge.total)} vaults lack purge protection. ` : ''}${rbac.pct !== null && rbac.pct < E_THRESHOLD ? `${fmt(rbac.total - rbac.good)} still use access policies instead of role-based access control.` : ''}`, 'Review retention requirements and application dependencies, then approve purge protection and the RBAC permission model.', 'Secret and key stores protected against deletion and governed by roles.', 'DP.2')
    if (segmentation.pct !== null && segmentation.pct < E_THRESHOLD) priority(12, 'Network segmentation', `${fmt(segmentation.total - segmentation.good)} of ${fmt(segmentation.total)} workload subnets have no network security group or firewall route.`, 'Apply segmentation to the workload subnets without it, starting with internet-facing and production ranges.', 'Every workload subnet is protected by platform, firewall or segmented controls.', 'NB.1')
    if (trusted.pct !== null && trusted.pct < E_THRESHOLD) priority(13, 'Platform integrity', `${fmt(trusted.total - trusted.good)} of ${fmt(trusted.total)} virtual machines run without Trusted Launch.`, 'Enable Secure Boot and virtual TPM on supported machines during planned maintenance.', 'Supported virtual machines run with platform integrity enforced.', 'EW.7')
    m.priorities.sort((a, b) => a.rank - b.rank)
    if (!m.priorities.length) priority(20, 'Baseline validation', 'The collected evidence does not identify an open hardening item.', 'Confirm the intended control scope with the client and complete any outstanding portal readings.', 'An agreed, evidence-backed baseline for the next review.', 'P0.1')

    // MFA methods: the users still signing in with text message or voice, which Microsoft retires, and the
    // stronger methods already in use. The report frames this as updating each user's MFA method, never as a
    // passwordless programme (Oct 14, 2026). Passkeys are the recommended target, Authenticator push stays
    // supported, and a telephony provider is kept only for a documented need. The HTML block and the deck share
    // the Microsoft timeline and the steps from here (Oct 16, 2026).
    if (count(retiring?.DistinctUsers) > 0 || count(resistant?.DistinctUsers) > 0) {
      const n = count(retiring?.DistinctUsers) ?? 0
      m.mfaMethods = {
        outcome: MFA_OUTCOME, retiring: n, resistant: count(resistant?.DistinctUsers) ?? 0, authenticator: count(authenticator?.DistinctUsers) ?? 0, phoneOnly, reliance,
        deadline: RETIREMENT.text, deadlineShort: RETIREMENT.shortText,
        timeline: `From September 1, 2026, Microsoft enables passkeys for users enabled for text message or voice and prompts them to register one when they complete MFA. Microsoft retires its text message and voice delivery on ${RETIREMENT.label} for most users and on ${RETIREMENT.later.label} for ${RETIREMENT.later.who}. After the applicable date, a user whose only available MFA method is Microsoft-provided text message or voice must register a passkey before signing in again, and this blocking prompt has no opt-out. A user moved to a telephony provider from Microsoft Security Store before that date does not receive it.`,
        steps: [
          ['Notify the affected users', `Each of the ${plural(n, 'user', 'users')} on text message or voice hears what changes, when, and to expect the passkey prompt.`],
          ['Register a phishing-resistant method', 'A passkey in Microsoft Authenticator, on Windows or on a FIDO2 key, or Windows Hello for Business, in guided waves. Authenticator push stays supported.'],
          ['Remove the retiring methods', 'Text message and voice leave the allowed methods under change control. A telephony provider stays only for a documented regulatory or operational need.'],
          ['Confirm readiness early', `A final sweep before ${RETIREMENT.shortText} confirms each affected user holds a replacement method.`]
        ],
        source: `${source('IA.2', 'Methods used in successful sign-ins, last 30 days.')}${phoneOnly !== null ? ` ${source('IA.5', 'Registered methods, members only.')}` : ''}`
      }
    }

    // Scores and posture. Each score records its model, where it was read, its scope and its read date (Oct 16, 2026).
    // Defender for Cloud offers two models with different calculations and values: the classic secure score in the
    // Azure portal, which Resource Graph (POS.1, securescores) and the continuous export (POS.7) carry, and the
    // risk-based Cloud Secure Score in the Defender portal, which no query here reads. Microsoft Secure Score is a
    // separate score for the Microsoft 365 tenant. The scope is a count, never an identifier.
    // A movement line compares two readings only when both use the same model and the same maximum. A different
    // maximum means the evaluated scope or the scoring changed between them, so the score reads as current state and
    // the evidence review or presenter notes name the two readings.
    const CLOUD_MODEL = 'Classic Defender for Cloud secure score', TENANT_MODEL = 'Microsoft Secure Score'
    const sameModel = (a, b) => clean(a).toLowerCase() === clean(b).toLowerCase()
    const sameMax = (a, b) => num(a) > 0 && num(b) > 0 && Number(a).toFixed(2) === Number(b).toFixed(2)
    const cloud = one('POS.1')
    const scoreValid = cloud && num(cloud.Current) !== null && num(cloud.Max) > 0 && cloud.Current <= cloud.Max
    const trendRows = rows('POS.7').filter(r => validDate(iso(r.Month)) && num(r.Percent) !== null && Number(r.Percent) <= 100).sort((a, b) => iso(a.Month).localeCompare(iso(b.Month)))
    if (scoreValid) {
      const value = pct(cloud.Current, cloud.Max)
      const first = trendRows[0], last = trendRows[trendRows.length - 1]
      // Movement is measured from the first month of the trend to the current score (POS.1), so the points and the
      // percentage on the page reconcile. The trend's own last month may differ from the current reading by a few tenths.
      // The gate is the current score against the first month: the export can lag the current reading, so its own
      // last point is not the truth about today.
      // The movement is stated in percentage points with the starting percentage (from), never as points available.
      // A movement that rounds to zero is no gain: the score then reads as current state everywhere.
      // Both readings are the classic model, so the gate is the maximum: the first month's against the current one.
      const cloudComparable = trendRows.length >= 2 && sameMax(first.Max, cloud.Max)
      const cloudPoints = cloudComparable ? Number((value - Number(first.Percent)).toFixed(1)) : null
      const delta = cloudPoints !== null && cloudPoints > 0 ? { points: cloudPoints, since: monthLabel(first.Month), from: Number(first.Percent) } : null
      const scope = plural(cloud.Subscriptions, 'subscription', 'subscriptions'), readTime = index.get('POS.1')?.ReadTimeUtc, read = validDate(iso(readTime)) ? date(readTime) : null
      m.cloudScore = { value, current: Number(cloud.Current), max: Number(cloud.Max), subscriptions: count(cloud.Subscriptions), model: CLOUD_MODEL, origin: 'Azure Resource Graph', scope, read, basis: `${CLOUD_MODEL} across ${scope}. ${read ? `Read ${read} from Azure Resource Graph.` : 'Read from Azure Resource Graph.'}`, delta, trend: trendRows.map(r => ({ label: monthLabel(r.Month), pct: Number(r.Percent) })), note: `${CLOUD_MODEL} across ${scope}, calculated by Microsoft. ${read ? `Read ${read} from Azure Resource Graph.` : 'Read from Azure Resource Graph, with no read date recorded.'}`, source: source('POS.1') }
      if (trendRows.length >= 2 && !cloudComparable) presenter('Defender for Cloud score movement', num(first.Max) > 0 ? `The continuous export reads a maximum of ${fmt(Number(first.Max))} points in ${monthLabel(first.Month)} and the current reading ${fmt(Number(cloud.Max))} points, so the evaluated scope or the scoring changed between them. The two are not compared and the score reads as current state. The report shows the monthly trend beside it.` : `The continuous export records no maximum for ${monthLabel(first.Month)}, so it is not compared with the current reading and the score reads as current state. The report shows the monthly trend beside it.`)
      else if (trendRows.length >= 2 && !delta) presenter('Defender for Cloud score movement', `The continuous export shows ${pctText(first.Percent)} in ${monthLabel(first.Month)} and ${pctText(last.Percent)} in ${monthLabel(last.Month)}. The report shows the monthly trend, including declines, beside the current score. Changes in the measurement model, scope or weighting can move the score without a change in the underlying controls.`)
      if (count(cloud.Subscriptions) !== m.subscriptions) presenter('Score subscription scope', `The cloud score covers ${fmt(cloud.Subscriptions)} of ${fmt(m.subscriptions)} in-scope subscriptions.`)
      if (count(cloud.Subscriptions) > 1) presenter('Score across subscriptions', `POS.1 adds the points of ${scope}. When the Azure portal combines subscriptions, Microsoft weights each one by its healthy and unhealthy resources, so the portal percentage can differ from this one.`)
    } else unmeasured('POS.1', 'Defender for Cloud score', state('POS.1'))
    // Tenant Secure Score: the reviewed context file wins, otherwise the Graph reading (POS.6) with movement from the 90-day trend.
    const pos6 = one('POS.6')
    const trend6 = rows('POS.6-TREND').filter(r => validDate(iso(r.Date)) && num(r.Current) !== null).sort((a, b) => iso(a.Date).localeCompare(iso(b.Date)))
    const graphTenant = pos6 && num(pos6.Current) !== null && num(pos6.Max) > 0 && validDate(iso(pos6.ReadDate)) ? {
      Current: Number(pos6.Current), Max: Number(pos6.Max), ReadDate: iso(pos6.ReadDate), Source: source('POS.6'),
      Categories: { Identity: pos6.IdentityPct, Device: pos6.DevicePct, Apps: pos6.AppsPct, Data: pos6.DataPct },
      ...(trend6.length >= 2 ? { Previous: Number(trend6[0].Current), PreviousMax: num(trend6[0].Max) > 0 ? Number(trend6[0].Max) : null, PreviousReadDate: iso(trend6[0].Date) } : {})
    } : null
    const tenant = context.TenantScore || graphTenant
    if (tenant && num(tenant.Current) !== null && num(tenant.Max) > 0 && tenant.Current <= tenant.Max && validDate(tenant.ReadDate) && clean(tenant.Source)) {
      const categories = ['Identity', 'Device', 'Apps', 'Data'].filter(k => num(tenant.Categories?.[k]) !== null && tenant.Categories[k] <= 100).map(k => ({ label: k, pct: Number(tenant.Categories[k]) }))
      // Movement in percentage points, each snapshot over its own maximum, so both scores read the same way. The
      // earlier reading keeps the maximum recorded with it (POS.6-TREND Max, or PreviousMax in the context file),
      // because Microsoft widens the maximum over time. A context reading without PreviousMax takes the maximum of
      // the POS.6-TREND snapshot dated PreviousReadDate. Without either, the movement line is omitted and the
      // evidence review says why, since a historical percentage over today's maximum is not evidence. A
      // percentage that has not risen prints no movement line.
      const value = pct(tenant.Current, tenant.Max)
      const snapshot = validDate(tenant.PreviousReadDate) ? trend6.find(r => iso(r.Date) === iso(tenant.PreviousReadDate) && num(r.Max) > 0) : null
      const previousMax = num(tenant.PreviousMax) > 0 ? Number(tenant.PreviousMax) : snapshot ? Number(snapshot.Max) : null
      // The earlier reading is compared only when it uses the same model (PreviousModel in the context file, Microsoft
      // Secure Score when absent) and the same maximum as the current reading.
      const previousModel = clean(tenant.PreviousModel) || TENANT_MODEL
      const tenantComparable = previousMax !== null && sameModel(previousModel, TENANT_MODEL) && sameMax(previousMax, tenant.Max)
      const previousPct = tenantComparable && num(tenant.Previous) !== null && tenant.Previous <= previousMax ? pct(tenant.Previous, previousMax) : null
      // A movement that rounds to zero is no gain, so no surface prints "Up 0 points".
      const tenantPoints = previousPct !== null ? Number((value - previousPct).toFixed(1)) : null
      const previous = tenantPoints !== null && tenantPoints > 0 && validDate(tenant.PreviousReadDate) ? { points: tenantPoints, since: monthLabel(tenant.PreviousReadDate), from: previousPct } : null
      if (num(tenant.Previous) !== null && previousMax === null) note('Microsoft tenant Secure Score movement', 'The context file gives a Previous reading without PreviousMax, and no POS.6-TREND snapshot is dated PreviousReadDate, so the movement line is omitted rather than measured against the current maximum. Add PreviousMax, the maximum at that reading, to show it.')
      const since = validDate(tenant.PreviousReadDate) ? date(tenant.PreviousReadDate) : 'an undated reading'
      if (num(tenant.Previous) !== null && previousMax !== null && !sameModel(previousModel, TENANT_MODEL)) note('Microsoft tenant Secure Score movement', `The earlier reading from ${since} uses ${previousModel} and the current reading uses ${TENANT_MODEL}, so the two are not compared and the score reads as current state.`)
      else if (num(tenant.Previous) !== null && previousMax !== null && !tenantComparable) note('Microsoft tenant Secure Score movement', `The earlier reading from ${since} has a maximum of ${fmt(previousMax)} points and the current reading ${fmt(Number(tenant.Max))} points, so the evaluated scope or the scoring changed between them. The two are not compared and the score reads as current state.`)
      const origin = tenant === graphTenant ? 'Microsoft Graph' : 'a reviewed portal reading'
      m.tenantScore = { value, current: Number(tenant.Current), max: Number(tenant.Max), model: TENANT_MODEL, origin, scope: 'Microsoft 365 tenant', read: date(tenant.ReadDate), basis: `${TENANT_MODEL}. Read ${date(tenant.ReadDate)} from ${origin}.`, delta: previous, categories, note: `${TENANT_MODEL} for the Microsoft 365 tenant, calculated by Microsoft. Read ${date(tenant.ReadDate)} from ${origin}.`, source: clean(tenant.Source) }
    } else note('Microsoft tenant Secure Score', 'Add a dated portal reading through the context file to show the tenant score beside the Defender for Cloud score. Optional Previous and PreviousReadDate fields add the movement line.')
    const high = rows('POS.4').find(r => /High/i.test(r.Severity))
    // POS.5 carries every assigned standard. The Microsoft cloud security benchmark is the one reported, so a preview
    // edition beside it or the CSPM scaffold never doubles the count. A tenant that holds only a versioned edition
    // (the v2 rollout) reports that one edition: the unversioned name first, then a versioned name that is not a
    // preview, then the latest preview. Named standards that are not the benchmark never stand in for it. Older
    // packs whose rows carry no standard name keep every row.
    const benchAll = rows('POS.5').filter(r => count(r.Passed) !== null && count(r.Failed) !== null)
    const MCSB = /^Microsoft[- ]cloud[- ]security[- ]benchmark/i
    const benchNames = [...new Set(benchAll.map(r => clean(r.Standard)).filter(n => MCSB.test(n)))]
    // Editions are ordered by their parsed version number (v10 after v9), never by the name as text.
    const edition = n => { const v = n.match(/v(\d+(?:\.\d+)*)/i); return v ? v[1].split('.').map(Number) : [0] }
    const byEdition = (a, b) => { const x = edition(a), y = edition(b); for (let i = 0; i < Math.max(x.length, y.length); i++) { const d = (y[i] || 0) - (x[i] || 0); if (d) return d } return a.localeCompare(b) }
    const benchName = benchNames.find(n => /^Microsoft[- ]cloud[- ]security[- ]benchmark$/i.test(n))
      || benchNames.filter(n => !/preview/i.test(n)).sort(byEdition)[0]
      || benchNames.sort(byEdition)[0] || null
    // Without a benchmark edition the meter is left unset. Only legacy rows with no Standard field at all count as
    // a whole, since those packs recorded the benchmark alone.
    const bench = benchName ? benchAll.filter(r => clean(r.Standard) === benchName) : benchAll.every(r => !clean(r.Standard)) ? benchAll : []
    m.posture = {
      estate: sum(rows('P0.5'), 'Resources'), assessed: count(one('POS.2')?.AssessedResources),
      highHealthy: high && count(high.Healthy) !== null && count(high.Total) > 0 ? { good: high.Healthy, total: high.Total, pct: pct(high.Healthy, high.Total), source: source('POS.4') } : null,
      benchmark: bench.length ? { passed: sum(bench, 'Passed'), total: sum(bench, 'Passed') + sum(bench, 'Failed'), pct: pct(sum(bench, 'Passed'), sum(bench, 'Passed') + sum(bench, 'Failed')), source: source('POS.5') } : null,
      // Healthy of assessed resources per control: resources is null when either count is missing or both are zero,
      // so no surface prints 0 of 0.
      scoreControls: rows('POS.3').filter(r => num(r.Current) !== null && num(r.Max) > 0 && r.Current <= r.Max).map(r => {
        const healthy = count(r.Healthy), unhealthy = count(r.Unhealthy)
        const resources = healthy !== null && unhealthy !== null && healthy >= 0 && unhealthy >= 0 && healthy + unhealthy > 0 ? healthy + unhealthy : null
        return { label: clean(r.Control), pct: pct(r.Current, r.Max), remaining: Number((r.Max - r.Current).toFixed(2)), healthy, unhealthy, resources }
      }).sort((a, b) => b.remaining - a.remaining),
      // How a classic score control earns points, from Microsoft's secure score page (dated Jun 30, 2026): within a
      // subscription or connector, the current score is the score per resource (the maximum over the healthy and
      // unhealthy resources) times the healthy resources, so a control gains points before it completes. POS.3 adds
      // the points and the resource counts of each control across subscriptions, so with more than one subscription
      // (or an unknown count) the page says the healthy share can differ from the share of points earned.
      scoreControlBasis: `Defender for Cloud secure score provides a standardized view of assessed cloud security controls. Within each subscription, a control earns points for every healthy resource it assesses, its maximum divided by its healthy and unhealthy resources in that subscription, so points can be gained before a control completes.${(count(cloud?.Subscriptions) ?? m.subscriptions) === 1 ? '' : ' The points and resource counts shown for each control are added across subscriptions, so the share of resources healthy can differ from the share of points earned.'} Changes in the score may reflect remediation activity, changes to the evaluated resource population, or differences in the underlying scoring model. Atmosera evaluates the individual findings, the affected resources and the controls in force alongside the Microsoft-calculated score.`,
      scoreControlSource: source('POS.3'), telemetryTables: telemetry, rules: ruleTotal !== null ? { total: ruleTotal, enabled: ruleEnabled } : null
    }

    // Delivered work from the reviewed context file.
    for (const item of array(context.Delivered)) {
      if (clean(item.Title) && clean(item.Outcome) && clean(item.Reference) && validDate(item.CompletedDate) && windowValid && item.CompletedDate >= p.WindowStart && item.CompletedDate <= p.WindowEnd) {
        m.delivered.push({ title: clean(item.Title), outcome: clean(item.Outcome), reference: clean(item.Reference), date: date(item.CompletedDate), pillar: clean(item.Pillar || '') })
      } else note('Delivery record needs review', 'A delivery entry was omitted because it lacks a title, outcome, reference or a completion date inside the alert period.')
    }
    if (!m.delivered.length) note('Delivered work', 'Add completed change references through the context file to show verified delivery on the roadmap page. Planned work is never labeled as delivered.')

    // Action status from the reviewed context file. Like Impact and OpenAlertNote, a record is bound to the alert
    // period it covers and reviewed on or after the posture read date, so a record from an earlier review never
    // carries a status forward to this collection's findings. Scheduled needs a target date, and Verified needs a
    // Delivered record in this period with the same reference. A record that fails a check is omitted with a note.
    const seenActions = new Set()
    for (const raw of array(context.Actions)) {
      const record = raw && typeof raw === 'object' ? raw : {}
      const key = clean(record.Key), status = String(record.Status ?? '')
      const reviewed = iso(record.Reviewed), recordStart = iso(record.WindowStart), recordEnd = iso(record.WindowEnd), target = record.TargetDate === undefined || record.TargetDate === null || record.TargetDate === '' ? null : iso(record.TargetDate)
      const omitted = reason => note('Action status needs review', `The context Actions record${key ? ` for ${key}` : ''} was omitted because ${reason} Correct it before presenting, or remove it to keep the item worded as a recommendation.`)
      // The detect item was split on Oct 16, 2026, when analytics rules and threat intelligence became foundational.
      if (key === 'detect') omitted('the detect item was retired on Oct 16, 2026. Use vulnassess for vulnerability assessment, and drift for analytics rules and threat intelligence, which are now foundational gaps.')
      else if (!ACTION_KEYS.includes(key)) omitted(`its Key is not one of ${ACTION_KEYS.join(', ')}.`)
      else if (seenActions.has(key)) omitted('another record already carries the same Key.')
      else if (!Object.prototype.hasOwnProperty.call(ACTION_STATUS, status)) omitted(`its Status is not one of ${Object.keys(ACTION_STATUS).join(', ')}.`)
      else if (!clean(record.Reference) || !validDate(reviewed) || !validDate(recordStart) || !validDate(recordEnd)) omitted('it lacks a Reference, a Reviewed date, or the WindowStart and WindowEnd of the alert period it covers.')
      else if (!windowValid || recordStart !== p.WindowStart || recordEnd !== p.WindowEnd) omitted(`it covers ${span(recordStart, recordEnd)} and this pack's alert period is ${m.period.label}.`)
      else if (!validDate(iso(p.PostureReadDate)) || reviewed < iso(p.PostureReadDate)) omitted(`its review is dated ${date(reviewed)}, before the evidence was collected on ${readDate}.`)
      else if (target !== null && !validDate(target)) omitted('its TargetDate is not a date.')
      else if (status === 'Scheduled' && target === null) omitted('a Scheduled item needs a TargetDate.')
      else if (status === 'Verified' && !m.delivered.some(d => d.reference === clean(record.Reference))) omitted('a Verified item needs a Delivered record in this alert period with the same Reference.')
      else {
        seenActions.add(key)
        m.actions.push({ key, status, label: ACTION_STATUS[status], owner: clean(record.Owner || ''), targetDate: target ? date(target) : '', verification: clean(record.Verification || ''), reference: clean(record.Reference), reviewed: date(reviewed), source: `Reviewed action status ${clean(record.Reference)}, ${date(reviewed)}, from the reviewed context file.` })
      }
    }

    // Pillar outcome rows. Each row leads with a statement earned by the strongest available measure. The strong
    // statement says every or all, so it needs a complete reading. A reading at E that still leaves resources out
    // takes the near statement instead, which leads with the ratio and the remainder (Oct 15, 2026).
    const band = (c, strong, near, partialText, weak) => c && c.pct !== null ? (c.pct >= E_THRESHOLD ? (complete(c) ? strong : near) : c.pct >= 50 ? partialText : weak) : null
    const measureText = c => c && c.pct !== null ? `${fmt(c.good)} of ${fmt(c.total)}` : null
    const remaining = c => `with ${fmt(c.total - c.good)} remaining`
    // keep holds the narrative sentences no surface may cut, and headlineShort the headline a crowded deck row may
    // fall back to before it touches them.
    const pillar = (name, headline, narrative, measure, callout, sourceText, extra = {}) => m.pillars.push({ name, headline: clean(headline), narrative: clean(narrative), measure: measure && measure.pct !== null ? { label: clean(measure.label), good: measure.good, total: measure.total, pct: measure.pct, mark: measure.mark } : null, callout: callout ? { value: clean(callout.value), label: clean(callout.label) } : null, source: clean(sourceText), ...(extra.keep ? { keep: clean(extra.keep) } : {}), ...(extra.headlineShort && extra.headlineShort !== headline ? { headlineShort: clean(extra.headlineShort) } : {}) })
    {
      const parts = []
      if (mfa.boolean) parts.push(isInForce(mfa) ? `Conditional Access requires multifactor authentication for every user on every application.${mfaRatio ? ` ${pctText(mfaRatio.pct)} of ${unevaluated !== null ? 'members whose sign-ins in the last 30 days could be evaluated' : 'members who signed in over the last 30 days'} satisfied it.` : ''}` : `${mfaPolicy}${mfaRatio ? ` ${pctText(mfaRatio.pct)} of ${unevaluated !== null ? 'members whose sign-ins in the last 30 days could be evaluated' : 'members who signed in over the last 30 days'} satisfied multifactor authentication.` : ''}`)
      else if (mfa.pct !== null) parts.push(`${pctText(mfa.pct)} of ${unevaluated !== null ? 'members whose sign-ins in the last 30 days could be evaluated' : 'members who signed in over the last 30 days'} satisfied multifactor authentication${externalMfa > 0 ? ', including sign-ins where a federated identity provider supplied the multifactor claim' : ''}.${legacyMfaQuery && mfa.pct < 50 ? ' Multifactor authentication completed through a federated identity provider is confirmed in the review.' : ''}`)
      // The split follows the share, and no deck row may cut it.
      if (mfaSplit && mfa.pct !== null) parts.push(mfaSplitNarrative)
      if (isInForce(locControl)) parts.push('Conditional Access restricts sign-ins by location for every user.')
      const legacyBlockedInForce = isInForce(legacyControl)
      if (legacyBlockedInForce) parts.push('Legacy authentication is blocked.')
      if (advancedPhish) parts.push('An advanced anti-phishing policy protects every mailbox.')
      else if (basicPhish) parts.push('The Microsoft default anti-phishing policy covers every mailbox.')
      const headline = band(mfa, legacyBlockedInForce ? 'Sign-ins are challenged and legacy protocols are blocked' : 'Sign-ins are challenged for multifactor authentication', `Multifactor authentication covers ${measureText(mfa)} ${unevaluated !== null ? 'evaluated members' : 'members'} at sign-in, ${remaining(mfa)}${legacyBlockedInForce ? ', and legacy protocols are blocked' : ''}`, 'Multifactor authentication covers most sign-ins, with full coverage sequenced', mfa.boolean ? 'Multifactor authentication policy coverage is the identity priority on the roadmap' : 'Multifactor coverage is the identity priority on the roadmap') || (isInForce(locControl) ? 'Conditional Access restricts sign-ins by location' : 'Identity readings are completed in the review')
      const mfaMeasureLabel = unevaluated !== null ? 'Evaluated members on MFA at sign-in' : 'Users challenged for MFA at sign-in'
      const mfaMeasure = mfa.boolean ? (mfaRatio ? { ...mfa, good: mfaRatio.good, total: mfaRatio.total, pct: mfaRatio.pct, mark: mark(mfaRatio.pct), label: mfaMeasureLabel } : null) : mfa.pct !== null ? { ...mfa, label: mfaMeasureLabel } : null
      pillar(G.identity, headline, parts.join(' ') || 'Sign-in telemetry was not available in this collection. Identity coverage is confirmed from the Entra admin center during the review.', mfaMeasure, m.mfaMethods && m.mfaMethods.resistant > 0 ? { value: fmt(m.mfaMethods.resistant), label: 'users already on phishing-resistant sign-in' } : null, mfa.pct !== null ? mfa.source : legacyBlockedInForce ? legacyControl.source : locControl.source, mfaSplit && mfa.pct !== null ? { keep: mfaSplitNarrative } : {})
    }
    {
      const parts = []
      if (edr.pct === null && String(p.DefenderApi || '').toLowerCase() !== 'available') parts.push('Endpoint telemetry was not reachable in this collection, so device coverage is confirmed from the Defender portal during the review.')
      // When EW.1-GAPS names machines that are not reporting, the coverage sentence and the reconciliation are kept
      // together on every surface, so the figure is never shown without the machines behind the remainder.
      const coverage = edr.pct !== null ? `Endpoint detection covers ${fmt(edr.good)} of ${fmt(edr.total)} eligible Azure virtual machines seen in the last 7 days${sensors.pct !== null ? `, with ${pctText(sensors.pct)} of onboarded Azure virtual machine sensors active` : ''}.${reconciliation && gapCount > 0 ? ' ' + reconciliation : ''}` : ''
      if (coverage) parts.push(coverage)
      if (vaControl.pct !== null) parts.push(`Vulnerability assessment covers ${pctText(vaControl.pct)} of onboarded Azure virtual machines.`)
      if (encryption.pct !== null) parts.push(encryption.pct >= 50 ? `Encryption at host is enabled on ${fmt(encryption.good)} of ${fmt(encryption.total)} virtual machines${encryption.pct < E_THRESHOLD ? ' and the remainder is sequenced on the roadmap' : ''}.` : `Encryption at host for the ${plural(encryption.total, 'virtual machine', 'virtual machines')} is sequenced on the roadmap.`)
      const edrLead = `Endpoint detection covers ${measureText(edr)} eligible Azure virtual machines`
      const edrHeadline = (near, partialText) => band(edr, 'Every eligible Azure virtual machine reports to endpoint detection', near, partialText, 'Endpoint onboarding is the workload priority on the roadmap')
      const headline = edrHeadline(`${edrLead}, ${remaining(edr)}`, 'Most eligible Azure virtual machines report to endpoint detection, with the remainder sequenced') || (encryption.pct !== null ? band(encryption, 'Virtual machines run with encryption at host', `Encryption at host is enabled on ${measureText(encryption)} virtual machines, ${remaining(encryption)}`, 'Encryption at host covers most virtual machines', 'Workload hardening is sequenced on the roadmap') : 'Endpoint readings are confirmed in the review')
      const kept = reconciliation && gapCount > 0 ? coverage : ''
      pillar(G.endpoint, headline, parts.join(' ') || 'Endpoint telemetry was not reachable in this collection. Device coverage is confirmed from the Defender portal during the review.', edr.pct !== null ? { ...edr, label: 'Eligible Azure virtual machines on endpoint detection' } : encryption, vaControl.pct !== null ? { value: pctText(vaControl.pct), label: 'vulnerability assessment coverage' } : encryption.pct !== null ? { value: `${fmt(encryption.good)} of ${fmt(encryption.total)}`, label: 'virtual machines with encryption at host' } : null, edr.pct !== null ? edr.source : encryption.source,
        { keep: kept, headlineShort: kept ? edrHeadline(edrLead, 'Most eligible Azure virtual machines report to endpoint detection') : '' })
    }
    {
      const parts = []
      if (boundaryCount !== null && windowValid) parts.push(boundaryCount > 0 ? `${plural(boundaryCount, 'boundary and egress detection was', 'boundary and egress detections were')} raised and triaged ${m.period.label}.` : `No boundary or egress detections were raised ${m.period.label}.`)
      if (segmentation.pct !== null) parts.push(`${pctText(segmentation.pct)} of workload subnets have platform, firewall or segmented controls in place${segmentation.pct < E_THRESHOLD ? `, and ${fmt(segmentation.total - segmentation.good)} would benefit from added segmentation` : ''}.`)
      if (https.pct !== null) parts.push(`${complete(https) ? 'Every published web app enforces HTTPS' : `${fmt(https.good)} of ${fmt(https.total)} published web apps enforce HTTPS`}.`)
      const lead = https.pct !== null ? https : segmentation
      const headline = band(https, 'Encryption in transit enforced on every published service', `Encryption in transit enforced on ${measureText(https)} published web apps, ${remaining(https)}`, 'Encryption in transit enforced on most published services', 'Transport hardening is sequenced on the roadmap') || band(segmentation, 'Segmentation enforced across workload subnets', `Segmentation covers ${measureText(segmentation)} workload subnets, ${remaining(segmentation)}`, 'Segmentation covers most workload subnets', 'Segmentation is the network priority on the roadmap') || 'Boundary detections investigated to a documented disposition'
      pillar(G.network, headline, parts.join(' ') || 'Network readings are completed in the review.', segmentation.pct !== null ? { ...segmentation, label: 'Workload subnets segmented' } : https, boundaryCount !== null ? { value: fmt(boundaryCount), label: 'boundary detections triaged' } : https.pct !== null ? { value: measureText(https), label: 'web apps enforcing HTTPS' } : null, lead.source)
    }
    {
      const parts = []
      // Public network access and purge protection share their resource's total, so each joins the sentence as a
      // ratio unless both readings in it are complete.
      const atE = c => c.pct !== null && c.pct >= E_THRESHOLD
      if (transfer.pct !== null) parts.push(complete(transfer) && complete(publicOff) ? 'All storage accounts require secure transfer and refuse public network access.' : `${complete(transfer) ? 'All' : `${fmt(transfer.good)} of ${fmt(transfer.total)}`} storage accounts require secure transfer.${atE(publicOff) ? ` ${fmt(publicOff.good)} of ${fmt(publicOff.total)} refuse public network access.` : ''}`)
      if (softDelete.pct !== null) parts.push(`Soft delete ${complete(softDelete) ? 'protects every Key Vault' : `protects ${fmt(softDelete.good)} of ${fmt(softDelete.total)} Key Vaults`}${complete(purge) ? ' and purge protection is in force' : atE(purge) ? `, and purge protection covers ${fmt(purge.good)} of ${fmt(purge.total)}` : ''}.`)
      if (backup.pct !== null) parts.push(backup.pct >= 50 ? (complete(backup) ? 'Every virtual machine carries a backup policy.' : `${fmt(backup.good)} of ${fmt(backup.total)} virtual machines carry a backup policy.`) : 'Backup coverage for the virtual machine estate is sequenced on the roadmap.')
      if (mailRemoved !== null && mailRemoved > 0) parts.push(`Malicious mail is removed after delivery, with ${fmt(mailRemoved)} removals in the last 30 days.`)
      // Key material is named in the strong statement only when soft delete is complete as well.
      const headline = band(transfer, complete(softDelete) ? 'Data in transit and key material are protected' : 'Secure transfer is required on every storage account', `Secure transfer is required on ${measureText(transfer)} storage accounts, ${remaining(transfer)}`, 'Transport protection covers most storage, with the remainder sequenced', 'Data transport hardening is sequenced on the roadmap') || band(softDelete, 'Key material cannot be silently lost', `Soft delete protects ${measureText(softDelete)} Key Vaults, ${remaining(softDelete)}`, 'Key Vault recovery covers most vaults', 'Key protection is sequenced on the roadmap') || 'Data protection readings are completed in the review'
      pillar(G.data, headline, parts.join(' ') || 'Data protection readings are completed in the review.', transfer.pct !== null ? { ...transfer, label: 'Storage accounts with secure transfer' } : softDelete, mailRemoved !== null && mailRemoved > 0 ? { value: fmt(mailRemoved), label: 'malicious messages removed after delivery, last 30 days' } : backup.pct !== null && backup.pct >= 90 ? { value: measureText(backup), label: 'virtual machines under Azure Backup' } : softDelete.pct !== null && softDelete.pct >= 90 ? { value: measureText(softDelete), label: 'Key Vaults protected by soft delete' } : transfer.pct !== null ? { value: measureText(transfer), label: 'storage accounts requiring secure transfer' } : null, transfer.pct !== null ? transfer.source : softDelete.source)
    }
    {
      const parts = []
      // Triage, closure and open status are kept apart: OUT.1 records that an alert closed, not how it was resolved,
      // and unclassified closures are named beside the closed count. OUT.1 reads each alert created in the period at
      // its latest state at collection, never at the period's end, so every status reads at or by collection (Oct 16, 2026).
      if (m.alerts) {
        const a = m.alerts
        parts.push(`The SOC triaged ${plural(a.triaged, 'alert', 'alerts')}${m.ticketed ? ` associated with the managed security service` : ''} ${m.period.label}.`)
        parts.push(`By collection, ${fmt(a.closed)} ${a.closed === 1 ? 'was' : 'were'} closed.${a.openSentence ? ` ${a.openSentence}` : ''}`)
        if (a.analystMode) parts.push(`Automation rules closed ${fmt(a.automation)} more.`)
        if (a.unclassified > 0) parts.push(`${plural(a.unclassified, 'closed alert carries', 'closed alerts carry')} no recorded classification.`)
      }
      if (m.response) parts.push(`High severity alerts closed at a median of ${m.response.median.value}.${m.response.median.belowFloor ? ` ${m.response.notes[0]}` : ''}`)
      if (plan.pct !== null) parts.push(`Workload protection covers ${pctText(plan.pct)} of eligible resources.`)
      if (ruleControl.mark && ruleEnabled > 0) parts.push(`${fmt(ruleEnabled)} analytics rules are active${ti && count(ti.Indicators) > 0 ? ` alongside ${fmt(ti.Indicators)} threat intelligence indicators` : ''}.`)
      // The disposition statement says every alert, so it needs a complete DR.10 reading of every workspace and an
      // OUT.1 reading with no open alert and no unclassified closure. Open alerts at collection lead the
      // statement with the closed and open counts from OUT.1. Otherwise a DR.10 reading of every workspace that
      // leaves closures undocumented, or that sits beside unclassified closures, gives its own ratio with its window.
      // Otherwise (DR.10 missing, unavailable, ungathered, without closures in the last 30 days, or partial because a
      // workspace failed or was excluded) the statement leads with the triaged count from OUT.1, the figure the
      // pillar's source line cites, so a partial DR.10 ratio never reads as the whole tenant. OUT.1 alone shows
      // nothing about closing comments, so it never earns every on its own (Oct 16, 2026).
      const wholeDispositions = dispositions && dispositions.pct !== null && !partial('DR.10')
      const openLead = !!m.alerts && m.alerts.open > 0
      const dispositionLed = !!m.alerts && !openLead && wholeDispositions
      const disposition = !m.alerts ? null
        : openLead ? `${fmt(m.alerts.closed)} of ${plural(m.alerts.triaged, 'alert', 'alerts')} closed, ${fmt(m.alerts.open)} open at collection`
        : dispositionLed && complete(dispositions) && m.alerts.unclassified === 0 ? 'Every alert closed with a documented disposition'
        : dispositionLed ? `${measureText(dispositions)} alerts closed in the last 30 days carry a documented disposition`
        : `${plural(m.alerts.triaged, 'alert', 'alerts')} triaged ${m.period.label}`
      const headline = disposition || band(plan, 'Workload protection covers the resource estate', `Workload protection covers ${measureText(plan)} eligible resources, ${remaining(plan)}`, 'Workload protection covers most of the resource estate', 'Workload protection scope is sequenced on the roadmap') || 'Detection coverage is confirmed in the review'
      // When DR.10 earns the statement the source line cites it beside OUT.1, so the statement traces to its evidence.
      // A reviewed open alert split in the narrative cites its record as well.
      const detectionSource = !m.alerts ? plan.source : [m.alerts.source, dispositionLed ? dispositions.source : '', m.alerts.openSplit ? m.alerts.openSplit.source : ''].filter(Boolean).join(' ')
      pillar(G.detection, headline, parts.join(' ') || 'Detection readings are completed in the review.', plan.pct !== null ? { ...plan, label: 'Eligible resources with workload protection' } : null, m.response ? { value: m.response.median.value, label: `median time to close, ${m.response.scope === 'High' ? 'high severity alerts' : 'all alerts'}` } : m.alerts ? { value: fmt(m.alerts.triaged), label: 'alerts triaged' } : null, detectionSource)
    }

    // Executive summary tiles and tiers.
    const tile = (label, value, sub, sourceText, tone = '') => m.headline.push({ label: clean(label), value: clean(value), sub: clean(sub), source: clean(sourceText), tone })
    if (m.service) tile('Months of managed security', fmt(m.service.months), 'Continuous coverage, not project work', `Service start ${m.service.start}, from the reviewed context file.`)
    else if (m.posture.assessed !== null) tile('Azure resources assessed by Defender for Cloud', fmt(m.posture.assessed), m.posture.estate !== null ? `Across ${fmt(m.posture.estate)} resources in the estate` : 'Continuous posture assessment', source('POS.2'))
    else if (m.posture.estate !== null) tile('Azure resources in the estate', fmt(m.posture.estate), 'Under managed security coverage', source('P0.5'))
    if (m.alerts) tile('Alerts triaged', fmt(m.alerts.triaged), m.alerts.analystMode ? `Plus ${fmt(m.alerts.automation)} closed by automation rules` : m.alerts.truePositives > 0 ? `${plural(m.alerts.truePositives, 'confirmed threat', 'confirmed threats')}, classified by the SOC` : m.detections ? `Across ${m.detections.sources}` : m.period.label, m.alerts.source)
    else if (m.detections) tile('Detections received', fmt(m.detections.total), `Across ${m.detections.sources}`, m.detections.source)
    // The 90th percentile is creation to recorded close, so the line claims triage and closure, never investigation
    // completion or resolution quality, which the evidence does not hold.
    // A median under 20 minutes or a 90th percentile over one hour carries its note on the tile as well.
    if (m.response) tile(m.response.median.label, m.response.median.value, [m.response.p90 ? `Nine in ten triaged and closed within ${m.response.p90.value}` : 'High severity alerts', ...m.response.notes.map(t => t.replace(/\.$/, ''))].join('. '), m.response.median.source)
    // The tile never claims an outcome: the sub-line is the reviewed impact determination when the context file
    // carries one, otherwise the tactic reading or the classification itself. When the determination drives the
    // sub-line the source line cites the reviewed record beside OUT.1, so the impact claim traces to its evidence.
    else if (m.alerts && m.alerts.truePositives !== null) tile('Confirmed threats', fmt(m.alerts.truePositives), m.impact && m.alerts.truePositives > 0 ? (m.impact.confirmed === 0 ? `No data exposure or business impact confirmed, reviewed ${m.impact.reviewed}` : `${fmt(m.impact.confirmed)} with confirmed data exposure or business impact`) : m.alerts.flaggedKnown && m.alerts.truePositives > 0 ? (m.alerts.flagged === 0 ? `None carried ${m.alerts.tacticPhrase}` : `${fmt(m.alerts.flagged)} carried ${m.alerts.tacticPhrase}`) : 'Alerts the SOC classified as true positives', m.impact && m.alerts.truePositives > 0 ? `${m.alerts.source} ${m.impact.source}` : m.alerts.source)
    else if (m.detections) tile('Detections received', fmt(m.detections.total), `Across ${m.detections.sources}`, m.detections.source)
    if (m.tenantScore) tile('Microsoft tenant Secure Score', pctText(m.tenantScore.value), m.tenantScore.delta ? `Up ${fmt(m.tenantScore.delta.points)} points since ${m.tenantScore.delta.since}, from ${pctText(m.tenantScore.delta.from)}` : `Read ${m.tenantScore.read}`, m.tenantScore.source, m.tenantScore.delta ? 'up' : '')
    else if (m.cloudScore) tile('Defender for Cloud secure score', pctText(m.cloudScore.value), m.cloudScore.delta && m.cloudScore.delta.points > 0 ? `Up ${fmt(m.cloudScore.delta.points)} points since ${m.cloudScore.delta.since}, from ${pctText(m.cloudScore.delta.from)}` : 'Classic Defender for Cloud score', m.cloudScore.source, m.cloudScore.delta && m.cloudScore.delta.points > 0 ? 'up' : '')
    m.headline = m.headline.slice(0, 4)

    const row = (tier, label, value, id) => { if (value !== null && value !== undefined && value !== '' && value !== 'Not available') m.tiers[tier].push({ label: clean(label), value: clean(String(value)), id }) }
    if (m.alerts) {
      // The deck band shows the first three rows, so the tier leads with what "Did the program hold" names: alerts,
      // confirmed threats and the reviewed impact determination when the context file holds one. The closed
      // share and the tactic reading follow. Tactic-qualified: the count is of tactics recorded on the alert,
      // never a verified outcome.
      row('outcomes', 'Alerts triaged', fmt(m.alerts.triaged), 'OUT.1')
      if (m.alerts.truePositives !== null) row('outcomes', 'Confirmed threats', fmt(m.alerts.truePositives), 'OUT.1')
      if (m.impact && m.alerts.truePositives > 0) row('outcomes', 'Confirmed data exposure or business impact', fmt(m.impact.confirmed), 'CONTEXT')
      if (m.alerts.resolvedPct !== null && m.alerts.resolvedPct >= 90) row('outcomes', 'Alerts closed', `${pctText(m.alerts.resolvedPct)}`, 'OUT.1')
      if (m.alerts.flaggedKnown) row('outcomes', `True positives whose alerts carried ${m.alerts.tacticPhrase}`, `${fmt(m.alerts.flagged)} of ${fmt(m.alerts.truePositives)}`, 'OUT.4')
    }
    if (m.response) {
      row('outcomes', m.response.median.label, m.response.median.value, 'OUT.2')
      if (m.response.p90) row('outcomes', m.response.p90.label, m.response.p90.value, 'OUT.2')
    }
    if (m.detections && m.tiers.outcomes.length < 6) row('outcomes', 'Detections correlated into alerts', fmt(m.detections.total), 'OUT.5')
    // Control tiers. Measured controls only, so an ungathered control never moves a count.
    const measuredIn = tier => m.controls.filter(c => c.tier === tier && c.measured !== false && c.pct !== null)
    m.tierSummary = Object.fromEntries([['foundational', TIERS.foundational], ['defense', TIERS.defense]].map(([tier, label]) => {
      const items = measuredIn(tier)
      return [tier, { label, enforced: items.filter(c => c.mark === 'E').length, measured: items.length, small: items.filter(c => c.smallSample).length, total: m.controls.filter(c => c.tier === tier).length }]
    }))
    const drift = measuredIn('foundational').filter(c => c.mark !== 'E')
    if (drift.length) presenter('Foundational controls below E', `${plural(drift.length, 'foundational control reads', 'foundational controls read')} below E: ${list(drift.map(c => `${c.label} (${c.id}, ${c.boolean ? c.value.toLowerCase() + (c.ratioText ? ', ' + c.ratioText : '') : pctText(c.pct)})`))}. The controls baseline expects every foundational control at E at each review, so have a fix date ready for each rather than carrying them on the roadmap. The evidence shows the current reading only, not whether a control was ever enforced before, so say below the baseline, never regressed.`)
    // A tier count that holds a control on a small sample names it beside the total (issue #24).
    const tierRow = (tier, label, id) => { const t = m.tierSummary[tier]; if (!t.measured) return; row('controls', label, `${fmt(t.enforced)} of ${fmt(t.measured)}`, id); if (t.small) m.tiers.controls[m.tiers.controls.length - 1].note = smallSampleText(t.small) }
    tierRow('foundational', 'Foundational controls enforced', 'TIER.FOUNDATIONAL')
    tierRow('defense', 'Defense in depth controls enforced', 'TIER.DEFENSE')
    const tierOrder = { E: 0, P: 1, N: 2 }
    for (const c of [mfa, edr, plan, antimalware, vaControl, transfer, softDelete, https, ruleControl, sensors, backup, segmentation].filter(c => c && c.pct !== null).sort((a, b) => tierOrder[a.mark] - tierOrder[b.mark])) {
      if (m.tiers.controls.length >= 6) break
      row('controls', c.label, c.total > 9999 ? pctText(c.pct) : c.value, c.id)
    }
    for (const h of m.hardening.filter(h => h.rank < 99).slice(0, 6)) row('hardening', h.label, hardenText(h), h.id)
    if (m.cloudScore) row('benchmark', 'Defender for Cloud score', pctText(m.cloudScore.value), 'POS.1')
    if (m.tenantScore) row('benchmark', 'Microsoft tenant Secure Score', pctText(m.tenantScore.value), 'POS.6')
    if (m.posture.benchmark) row('benchmark', 'Benchmark controls passed', `${fmt(m.posture.benchmark.passed)} of ${fmt(m.posture.benchmark.total)}`, 'POS.5')
    if (m.posture.highHealthy) row('benchmark', 'High severity assessments healthy', pctText(m.posture.highHealthy.pct), 'POS.4')
    if (m.posture.assessed !== null) row('benchmark', 'Resources assessed by Defender for Cloud', fmt(m.posture.assessed), 'POS.2')
    for (const c of (m.tenantScore?.categories || [])) { if (m.tiers.benchmark.length < 6) row('benchmark', `${c.label} category score`, pctText(c.pct), 'POS.6') }
    m.whatNext = `The foundational and defense in depth controls we hold this environment to across five pillars, the status of each, ${m.period.months ? `${plural(m.period.months, 'month', 'months')} of measured outcomes` : 'the measured outcomes'}, the proposed hardening roadmap${m.mfaMethods && m.mfaMethods.retiring > 0 ? ` and the recommended MFA method update ahead of ${RETIREMENT.text}` : ''}.`

    // Presenter notes and boundaries.
    const manual = m.manifest.filter(r => r.status === 'MANUAL').map(r => r.id)
    if (manual.length) note('Manual portal readings', `${manual.join(', ')} are portal readings. Complete them before the review if the related statements are needed.`)
    const partials = m.manifest.filter(r => r.status === 'PARTIAL' && !r.id.endsWith('-BY-WORKSPACE'))
    if (partials.length) presenter('Partial collection', `${partials.map(r => r.id).join(', ')} completed with partial scope. Affected figures carry the partial label in their source line.`)
    if (m.notApplicable.length) note('Controls without evidence either way', `${m.notApplicable.map(u => `${u.label} (${u.id})`).join('. ')}. These read N/A on the controls page because the collection holds no activity or configuration to judge them by. They are excluded from every count.`)
    if (m.unmeasured.length) note('Controls not measured in this collection', `${m.unmeasured.map(u => `${u.label} (${u.id}: ${u.reason})`).join('. ')}. These appear as (null) on the controls page rather than as measured gaps, and they are excluded from the executive summary tiers.`)
    if (String(p.DefenderApi || '').toLowerCase() !== 'available' && p.DefenderApi) presenter('Defender API', `Defender Advanced Hunting was not reachable: ${clean(p.DefenderApi)}. Endpoint readings come from the portal for this review.`)
    note('Presentation boundaries', 'Alert closure does not confirm containment. Detections do not prove triage. No claim of zero data loss, SLA attainment, a control grade or completed hardening is generated from these aggregates.')
    note('Scope and time', `Alert activity covers ${m.period.label}. Identity and endpoint readings use the source lookback, generally the last 30 days. Azure configuration and score readings reflect ${readDate}.`)
    for (const issue of m.issues) note('Evidence file', issue)
    m.coverage = {
      available: m.manifest.filter(r => ['OK','EMPTY'].includes(r.status) && !r.id.endsWith('-BY-WORKSPACE')).length,
      total: m.manifest.filter(r => !r.id.endsWith('-BY-WORKSPACE')).length
    }
    return m
  }
  const api = { build, ACTION_KEYS, ACTION_STATUS, MFA_OUTCOME, fmt, clean, date, span, num, count, sum, duration, mark, pct, pctText, plural, MEDIAN_FLOOR, E_THRESHOLD, MIN_SAMPLE, smallSampleText, RETIREMENT, TIERS, NULL_VALUE: '(null)', NA_VALUE: 'N/A', MOSTLY_VALUE: 'Mostly enforced' }
  if (typeof module !== 'undefined' && module.exports) module.exports = api
  else root.EbrReport = api
})(typeof globalThis !== 'undefined' ? globalThis : this)
