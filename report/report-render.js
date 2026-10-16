(function () {
  'use strict'
  const { build, fmt, clean, pctText, plural } = EbrReport
  const data = JSON.parse(document.getElementById('report-data').textContent)
  const m = build(data)
  const esc = value => clean(value).replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/'/g, '&#39;')
  const report = document.getElementById('report')
  const SEVERITY = ['High', 'Medium', 'Low', 'Informational']
  const source = text => text ? `<p class="source">${esc(text)}</p>` : ''
  const clamp = v => Math.max(0, Math.min(100, Number(v) || 0))
  const bar = (pct, label, tone = '') => `<div class="track" role="img" aria-label="${esc(label)}"><span class="fill ${tone}" style="width:${clamp(pct).toFixed(2)}%"></span></div>`
  const ring = (pct, label, tone = '') => {
    const r = 42, c = 2 * Math.PI * r, v = clamp(pct)
    return `<svg class="ring ${tone}" viewBox="0 0 100 100" role="img" aria-label="${esc(label)}"><circle class="ring-track" cx="50" cy="50" r="${r}"/><circle class="ring-fill" cx="50" cy="50" r="${r}" stroke-dasharray="${(c * v / 100).toFixed(2)} ${c.toFixed(2)}" transform="rotate(-90 50 50)"/><text x="50" y="54" text-anchor="middle">${esc(pctText(pct))}</text></svg>`
  }
  const sparkline = (points, label) => {
    if (!points || points.length < 2) return ''
    const w = 220, h = 54, pad = 6
    const values = points.map(p => p.pct), lo = Math.min(...values), hi = Math.max(...values), range = hi - lo || 1
    const xy = points.map((p, i) => [pad + i * (w - 2 * pad) / (points.length - 1), h - pad - (p.pct - lo) * (h - 2 * pad) / range])
    const last = xy[xy.length - 1]
    return `<svg class="spark" viewBox="0 0 ${w} ${h}" role="img" aria-label="${esc(label)}"><polyline points="${xy.map(p => p.map(n => n.toFixed(1)).join(',')).join(' ')}"/><circle cx="${last[0].toFixed(1)}" cy="${last[1].toFixed(1)}" r="4"/></svg><div class="spark-axis"><span>${esc(points[0].label)}</span><span>${esc(points[points.length - 1].label)}</span></div>`
  }
  // A control at E that leaves resources out names its exceptions, so meeting the threshold reads differently from
  // having none left out (Oct 15, 2026).
  const exceptionText = c => c.exceptions > 0 ? plural(c.exceptions, 'exception', 'exceptions') : ''
  const markChip = (mark, exceptions = '') => mark ? `<span class="mark mark-${mark.toLowerCase()}" title="${mark === 'E' ? 'Enforced' : mark === 'P' ? 'Partial' : 'Not enforced'}${exceptions ? `, ${esc(exceptions)}` : ''}">${mark}</span>` : ''
  const footer = (number, topic) => `<footer class="page-footer"><span class="wordmark">atmosera<span>.</span></span><span>${esc(m.client)} · ${esc(topic)}</span><span>${number}</span></footer>`
  const heading = (n, title, subtitle) => `<header class="section-heading"><p class="eyebrow">Security business review · ${n}</p><h2>${esc(title)}</h2><p>${esc(subtitle)}</p></header>`
  const scopeLine = `${esc(m.period.label)} · Posture read ${esc(m.readDate)} · ${m.subscriptions} ${m.subscriptions === 1 ? 'subscription' : 'subscriptions'} · ${m.workspaces.length} Sentinel ${m.workspaces.length === 1 ? 'workspace' : 'workspaces'}`

  // 01 Executive summary
  const tiles = m.headline.map(t => `<article class="tile"><span class="tile-value">${esc(t.value)}</span><h3>${esc(t.label)}</h3><p class="${t.tone === 'up' ? 'up' : ''}">${esc(t.sub)}</p>${source(t.source)}</article>`).join('')
  const tierDefs = [
    ['outcomes', 'Tier 1 · Outcomes', 'Did the program hold'],
    ['controls', 'Tier 2 · Control effectiveness', 'What is actually enforced'],
    ['hardening', 'Tier 3 · What we are hardening next', 'Proposed in priority order'],
    ['benchmark', 'Tier 4 · Vendor benchmark', 'Context, not the objective']
  ]
  const tiers = tierDefs.map(([key, eyebrow, title]) => `<div class="tier tier-${key}"><p class="eyebrow">${esc(eyebrow)}</p><h3>${esc(title)}</h3>${m.tiers[key].length ? m.tiers[key].map(r => `<div class="tier-row"><span>${esc(r.label)}</span><strong>${esc(r.value)}</strong></div>`).join('') : `<p class="tier-empty">${key === 'hardening' ? 'No open hardening items from this collection.' : 'Readings are completed in the review.'}</p>`}</div>`).join('')
  const summary = `<section class="page summary-page" id="summary">
    <header class="hero"><p class="eyebrow">Managed security services · Executive business review</p><h1>Security: Executive Summary</h1><div class="hero-rule"></div><p class="hero-client">${esc(m.client)}</p><p class="hero-caption">Managed security, measured in alerts triaged, controls enforced and posture advanced.</p><p class="hero-meta">${scopeLine}</p></header>
    <div class="page-body">
      <div class="strip"><p class="strip-title">Managed security services in force</p><div class="tiles tiles-${m.headline.length}">${tiles}</div></div>
      <div class="tiers-block"><h2>How we report posture</h2><p>Posture is reported for the whole tenant, not for Azure resources alone, and never as a single vendor percentage. We weight what we report in this order.</p><div class="tiers">${tiers}</div></div>
      <div class="what-next"><span class="eyebrow">What comes next</span><p>${esc(m.whatNext)}</p></div>
    </div>${footer('01', 'Executive summary')}</section>`

  // 02 Security operations
  const responseTiles = []
  if (m.response) responseTiles.push({ value: m.response.median.value, label: m.response.median.label, sub: m.response.median.note, source: m.response.median.source })
  if (m.response?.p90) responseTiles.push({ value: m.response.p90.value, label: m.response.p90.label, sub: m.response.p90.note, source: m.response.p90.source })
  if (m.alerts) responseTiles.push({ value: fmt(m.alerts.triaged), label: `Alerts triaged${m.detections ? ' across ' + m.detections.sources : ''}`, sub: m.alerts.analystMode ? `${fmt(m.alerts.automation)} more were closed by automation rules.` : `${esc(m.period.label)}.`, source: m.alerts.source })
  // The tactic tile counts a tactic Sentinel recorded on the alert, never an outcome, and the confirmed threat tile
  // counts a classification, never an investigation. The impact determination is printed under the threats table.
  if (m.alerts && m.alerts.truePositives !== null && responseTiles.length < 4) responseTiles.push({ value: m.alerts.flaggedKnown ? fmt(m.alerts.flagged) : fmt(m.alerts.truePositives), label: m.alerts.flaggedKnown ? `True positives whose alerts carried ${m.alerts.tacticPhrase}` : 'Confirmed threats', sub: m.alerts.flaggedKnown ? `Of ${fmt(m.alerts.truePositives)} alerts the SOC classified as true positives ${esc(m.period.label)}. A tactic recorded on the alert, not a verified outcome.` : 'Alerts the SOC classified as true positives.', source: m.alerts.source })
  if (m.detections && responseTiles.length < 4) responseTiles.push({ value: fmt(m.detections.total), label: 'Detections correlated into alerts', sub: `Across ${m.detections.sources}.`, source: m.detections.source })
  const responseStrip = responseTiles.length ? `<div class="strip"><p class="strip-title">Response performance · measured, not asserted</p><div class="tiles tiles-${responseTiles.length}">${responseTiles.map(t => `<article class="tile"><span class="tile-value">${esc(t.value)}</span><h3>${esc(t.label)}</h3><p>${esc(t.sub)}</p>${source(t.source)}</article>`).join('')}</div></div>` : ''
  // One fixed cohort, with time to acknowledge beside time to close. When automation rules closed any of it, the
  // analyst-handled and automation-closed rows follow, labelled. The collector records no timing for automation
  // closures alone, so that row carries the count only.
  const r = m.response, cellOf = v => v ? esc(v.value) : 'Not available'
  const timingRows = r ? [
    ['All high severity alerts', r.n, r.acknowledge, r.median, r.p90],
    ...(r.split ? [r.split.analyst ? ['Analyst-handled', r.split.analyst.n, r.split.analyst.acknowledge, r.split.analyst.median, r.split.analyst.p90] : null, [r.split.automation.label, r.split.automation.n, null, null, null, 'Not collected']].filter(Boolean) : [])
  ] : []
  const responseDetail = r ? `<div class="timing"><h3>Response timing, high severity alerts</h3><div class="table-scroll"><table><caption>${esc(r.cohort)}</caption><thead><tr>${['Alerts', 'Closed', 'Median to acknowledge', 'Median to close', '90th percentile close'].map((h, i) => `<th scope="col"${i ? ' class="num"' : ''}>${h}</th>`).join('')}</tr></thead><tbody>${timingRows.map(([label, n, ack, median, p90, missing]) => `<tr><th scope="row">${esc(label)}</th><td class="num">${fmt(n)}</td>${[ack, median, p90].map(v => `<td class="num">${missing || cellOf(v)}</td>`).join('')}</tr>`).join('')}</tbody></table></div><p class="small">Acknowledge is the first status change from New, by an analyst or an automation rule. Close is creation to recorded close.${r.notes.length ? ` ${esc(r.notes.join(' '))}` : ''}</p>${r.target ? `<p class="small">${esc(r.target.sentence)}</p>` : ''}${source(r.median.source)}${r.split?.analyst ? source(r.split.analyst.source) : ''}${r.target ? source(r.target.source) : ''}</div>` : ''
  const trendRows = m.trend.slice(-12)
  const SEV = SEVERITY.filter(k => k !== 'Informational' || m.trend.some(r => r.Informational > 0))
  const maxTotal = Math.max(1, ...trendRows.map(r => r.Total))
  const chart = trendRows.length ? `<div class="chart" role="img" aria-label="Alerts created each month by severity. Exact values follow in the data table.">
    ${trendRows.map(r => `<div class="chart-row"><span class="chart-month">${esc(r.label)}</span><div class="stack" style="width:${(r.Total / maxTotal * 100).toFixed(2)}%">${SEV.filter(k => r[k] > 0).map(k => `<span class="sev-${k.toLowerCase()}" style="flex:${r[k]}"></span>`).join('')}</div><strong>${fmt(r.Total)}</strong></div>`).join('')}
    <div class="legend">${SEV.map(k => `<span><i class="sev-${k.toLowerCase()}"></i>${k}</span>`).join('')}</div></div>` : '<div class="empty-state">Monthly alert figures are completed in the review.</div>'
  const trendTable = m.trend.length ? `<details class="data-details"><summary>Monthly alert data</summary><div class="table-scroll"><table><caption>Alerts created each month, ${esc(m.period.label)}</caption><thead><tr>${['Month', 'Total', ...SEV].map(v => `<th scope="col">${v}</th>`).join('')}</tr></thead><tbody>${m.trend.map(r => `<tr><th scope="row">${esc(r.label)}</th>${['Total', ...SEV].map(k => `<td>${fmt(r[k])}</td>`).join('')}</tr>`).join('')}</tbody></table></div></details>` : ''
  // The panel says closed, never resolved: a closure can carry no classification, and the unclassified count is
  // named beside the closed count. Open alerts take the model's sentence, split only by a reviewed record.
  const openPara = a => a.open > 0 ? `${fmt(a.open)} ${a.open === 1 ? 'alert was' : 'alerts were'} open at collection. ${a.openSplit ? `Of these, ${esc(a.openSplit.phrase)}.` : 'These are items referred to the client for action or confirmation under the agreed notification process, together with investigations still in progress.'}` : 'No alert created in the period was open at collection.'
  const disposition = m.alerts ? `<aside class="panel"><p class="eyebrow">Alert disposition</p>${ring(m.alerts.resolvedPct, `${fmt(m.alerts.closed)} of ${fmt(m.alerts.triaged)} alerts closed`)}<h3>${fmt(m.alerts.closed)} alerts closed</h3><p>${openPara(m.alerts)}</p>${m.alerts.unclassified > 0 ? `<p class="small">${fmt(m.alerts.unclassified)} closed ${m.alerts.unclassified === 1 ? 'alert carries' : 'alerts carry'} no recorded classification.</p>` : ''}${m.alerts.analystMode ? `<p class="small">${fmt(m.alerts.automation)} additional alerts were closed by automation rules and are shown separately from analyst activity.</p>` : m.alerts.automation ? `<p class="small">Automation rules closed ${fmt(m.alerts.automation)} of the closed alerts.</p>` : ''}${source(m.alerts.source)}${m.alerts.openSplit ? source(m.alerts.openSplit.source) : ''}</aside>` : '<aside class="panel"><p class="eyebrow">Alert disposition</p><h3>Completed in the review</h3><p>The combined alert result is reconciled before dispositions are presented.</p></aside>'
  const maxSource = m.detections ? Math.max(1, ...m.detections.bySource.map(s => s.total)) : 1
  // The period as a phrase, as the story layer words it, without the quarter label.
  const periodPhrase = m.period.valid ? `from ${esc(m.period.label)}` : 'in the period'
  const detections = m.detections ? `<div class="sources"><h3>Detections by source</h3><p class="small">${fmt(m.detections.total)} detections ${periodPhrase} were correlated into the alerts above.</p>${m.detections.bySource.slice(0, 6).map(s => `<div class="source-row"><span>${esc(s.name)}</span>${bar(s.total / maxSource * 100, `${s.name}: ${fmt(s.total)} detections`)}<strong>${fmt(s.total)}</strong></div>`).join('')}${source(m.detections.source)}</div>` : ''
  // The impact statement prints with or without screened examples: a pack whose titles are all withheld, or whose
  // rows carry no titles or tactics, still has true positives, so the block carries the count and the statement.
  const impactPara = m.impactStatement ? `<p class="small impact">${esc(m.impactStatement)}</p>` : ''
  const impactSource = m.impact ? source(m.impact.source) : ''
  const threats = m.threats ? `<div class="threats"><h3>Confirmed threats</h3><p class="small">Alerts the SOC classified as true positives ${periodPhrase}, grouped by alert title, highest severity first.</p><div class="table-scroll"><table><caption>Confirmed threat examples</caption><thead><tr>${['Threat', 'Alerts', 'Severity', 'Attack stage', 'When'].map(h => `<th scope="col"${h === 'Alerts' ? ' class="num"' : ''}>${h}</th>`).join('')}</tr></thead><tbody>${m.threats.examples.map(t => `<tr><th scope="row">${esc(t.title)}</th><td class="num">${fmt(t.alerts)}</td><td>${esc(t.severity)}</td><td>${esc(t.stage)}</td><td>${esc(t.when).replace(/ (\d{4})/g, '&nbsp;$1')}</td></tr>`).join('')}</tbody></table></div>${m.threats.more ? `<p class="small">And ${esc(plural(m.threats.moreAlerts, 'more confirmed alert', 'more confirmed alerts'))} in ${esc(plural(m.threats.more, 'further group', 'further groups'))}.</p>` : ''}${impactPara}${source(m.threats.source)}${impactSource}</div>`
    : impactPara ? `<div class="threats"><h3>Confirmed threats</h3><p class="small">${fmt(m.alerts.truePositives)} ${m.alerts.truePositives === 1 ? 'alert' : 'alerts'} the SOC classified as ${m.alerts.truePositives === 1 ? 'a true positive' : 'true positives'} ${periodPhrase}.</p>${impactPara}${source(m.alerts.source)}${impactSource}</div>` : ''
  const outcomes = `<section class="page balanced-only" id="outcomes">${heading('02', 'Security operations', 'What the managed security service handled, and how quickly')}
    <div class="page-body"><p class="section-scope">${scopeLine}</p>${responseStrip}${responseDetail}
    <div class="two-col"><div><h3>Alerts ${m.ticketed ? 'worked' : 'created'} each month</h3><p class="small">${m.ticketed ? 'Each alert opened a ticket and was worked inside the managed service. Volume reflects detection coverage and activity across the environment.' : 'Volume reflects detection coverage and activity across the environment. Each alert is triaged inside the managed service.'}</p>${chart}${trendRows.length < m.trend.length ? '<p class="small">Chart shows the most recent 12 months. The table contains the full period.</p>' : ''}${source(m.trendSource)}${trendTable}${detections}</div>${disposition}</div>${threats}
    <div class="decision-note"><h3>How to read this page</h3><p>${m.ticketed ? 'An alert is a Sentinel record that opened a ticket with the managed security service. Informational severity is excluded, and detections are the alerts correlated into those tickets.' : 'Detections from Sentinel, Defender for Cloud and the Defender services are correlated into alerts.'} The SOC triages each alert, and a closure records its classification when the SOC sets one${m.response ? `. Response times are measured from alert creation to recorded close for ${esc(m.response.cohort.charAt(0).toLowerCase() + m.response.cohort.slice(1))}` : ''}.</p></div>
    </div>${footer('02', 'Security operations')}</section>`

  // 03 Measured outcomes across every pillar
  const pillarRows = m.pillars.map((p, i) => `<article class="pillar-row"><div class="pillar-name"><span>0${i + 1}</span><h3>${esc(p.name)}</h3></div><div class="pillar-story"><h4>${esc(p.headline)}</h4><p>${esc(p.narrative)}</p>${source(p.source)}</div><div class="pillar-measure">${p.measure ? `<p class="measure-label">${esc(p.measure.label)}</p>${bar(p.measure.pct, `${p.measure.label}: ${fmt(p.measure.good)} of ${fmt(p.measure.total)}`, p.measure.pct >= 95 ? 'green' : '')}<strong>${fmt(p.measure.good)} of ${fmt(p.measure.total)}</strong>` : ''}</div><div class="pillar-callout">${p.callout ? `<strong>${esc(p.callout.value)}</strong><span>${esc(p.callout.label)}</span>` : ''}</div></article>`).join('')
  const measured = `<section class="page balanced-only" id="measured">${heading('03', 'Measured outcomes across every pillar', 'Each pillar and the outcome it produced')}
    <div class="page-body"><p class="section-scope">${scopeLine}</p><div class="pillars">${pillarRows}</div>
    <div class="decision-note"><h3>Why this matters</h3><p>Detection and response is the pillar Atmosera operates directly. The pillars that read lower are the ones that need change inside the client infrastructure, and each of those items is on the proposed roadmap. A vendor hands you a percentage. This is a program somebody runs.</p></div>
    </div>${footer('03', 'Measured outcomes')}</section>`

  // 04 The controls that matter
  const groups = ['Identity and access', 'Endpoint and workload', 'Network and boundary', 'Data protection', 'Detection and response']
  const nullRow = c => `<div class="control-row unmeasured"><span class="mark mark-null" title="Not gathered" aria-hidden="true"></span><div class="control-text"><h4>${esc(c.label)}</h4><p>${esc(c.note)}</p>${source(c.source)}</div><div class="control-measure"><strong>${esc(c.value)}</strong><span>Not gathered</span></div></div>`
  const naRow = c => `<div class="control-row unmeasured not-applicable"><span class="mark mark-null" title="No evidence either way" aria-hidden="true"></span><div class="control-text"><h4>${esc(c.label)}</h4><p>${esc(c.note)}</p>${source(c.source)}</div><div class="control-measure"><strong>${esc(c.value)}</strong><span>No evidence either way</span></div></div>`
  // The measure column: the figure, a bar for every measured ratio (a Mostly enforced policy carries the sign-in
  // ratio behind it), then the share and what the control is missing, such as the resource types outside coverage.
  const measureText = c => c.boolean ? (c.ratioText ? `${esc(c.ratioText)} · ${pctText(c.pct)}` : '') : c.total > 9999 ? `${esc(c.value)} sign-ins` : `${pctText(c.pct)}${c.estimate ? ' estimated' : ''}`
  const gapText = c => c.gap ? `<span class="gap">${esc(c.gap)}</span>` : ''
  const exceptionsLine = c => exceptionText(c) ? `<span class="exceptions">${esc(exceptionText(c))}</span>` : ''
  const controlRow = c => c.na ? naRow(c) : c.measured === false ? nullRow(c) : `<div class="control-row">${markChip(c.mark, exceptionText(c))}<div class="control-text"><h4>${esc(c.label)}</h4><p>${esc(c.note)}</p>${source(c.source)}</div><div class="control-measure"><strong>${esc(c.boolean ? c.value : c.total > 9999 ? pctText(c.pct) : c.value)}</strong>${c.boolean && !c.ratioText ? '' : bar(c.pct, `${c.label}: ${c.ratioText || c.value}`, c.mark === 'E' ? 'green' : c.mark === 'N' ? 'amber' : '')}<span>${measureText(c)}</span>${exceptionsLine(c)}${gapText(c)}</div></div>`
  // Each pillar shows its foundational controls on the left and its defense in depth controls on the right.
  const tierCols = [['foundational', 'Foundational'], ['defense', 'Defense in depth']]
  const tierCol = (items, tier, label) => {
    const rows = items.filter(c => c.tier === tier)
    const measured = rows.filter(c => c.measured !== false && c.pct !== null)
    const count = measured.length ? `${measured.filter(c => c.mark === 'E').length} of ${measured.length} enforced` : rows.length && rows.every(c => c.na) ? 'Not applicable' : rows.length ? 'Not gathered' : ''
    return `<div class="control-col ${tier}"><p class="tier-label"><span class="tier-name">${esc(label)}</span><span class="tier-count">${esc(count)}</span></p>${rows.map(controlRow).join('') || '<p class="tier-empty">Nothing to show for this pillar in this collection.</p>'}</div>`
  }
  const matrix = groups.map((group, i) => {
    const items = m.controls.filter(c => c.group === group)
    const counts = { E: items.filter(c => c.mark === 'E').length, P: items.filter(c => c.mark === 'P').length, N: items.filter(c => c.mark === 'N').length, U: items.filter(c => c.measured === false && !c.na).length, A: items.filter(c => c.na).length }
    return `<section class="pillar"><div class="pillar-head"><span>0${i + 1}</span><h3>${group}</h3><p class="small">${items.length ? `${counts.E} enforced · ${counts.P} partial · ${counts.N} not yet enforced${counts.U ? ` · ${counts.U} not gathered` : ''}${counts.A ? ` · ${counts.A} not applicable` : ''}` : 'Readings completed in the review'}</p></div><div class="control-list">${items.length ? tierCols.map(([tier, label]) => tierCol(items, tier, label)).join('') : '<p class="small">Evidence for this pillar is confirmed from the portal during the review.</p>'}</div></section>`
  }).join('')
  const controls = `<section class="page balanced-only" id="controls">${heading('04', 'The controls that matter', 'The standards we hold this environment to, and the status of each')}
    <div class="page-body"><p class="section-scope">Posture read ${esc(m.readDate)}. Activity lookbacks are stated with each measure.</p>
    <div class="legend-box"><h3>Two tiers of controls</h3><p><strong>Foundational</strong> controls are the baseline the managed security service holds every environment to, and each is expected to read enforced at every review. One that reads below E is a gap against that baseline and carries a fix date. <strong>Defense in depth</strong> controls are the additional safeguards layered on top. Each waits on something your team approves, schedules or licenses, and they are sequenced on the roadmap.</p>
    <h3>What the status marks mean</h3><p><span class="mark mark-e">E</span> Enforced on 90 percent or more of in-scope resources. <span class="mark mark-p">P</span> Partial, enforced on 50 to 89 percent. <span class="mark mark-n">N</span> Not yet enforced, under 50 percent. A ratio control at E that still leaves resources out shows how many as exceptions beside its figure, so meeting the threshold reads differently from complete coverage. A policy control reads In force when the policy covers every user on every application in every condition, Mostly enforced when an enabled policy stops short of that, by selecting its users or applications or by a platform, risk level, device filter or location condition, and at least half of the measured sign-ins still satisfied it, and Not in force otherwise. The percentage bands apply to ratio controls. A policy that stops short of every user on every application in every condition reads P however high the sign-in ratio behind it, because the policy itself is not in force everywhere. A control reading (null) could not be gathered in this collection and is confirmed from the portal during the review. A control reading N/A had no activity or configuration in this collection to judge it by, so it carries no status. Every reading describes the state at collection, not a change since the last review.</p></div>
    <div class="control-matrix">${matrix}</div></div>${footer('04', 'The controls that matter')}</section>`

  // 05 Delivered and sequenced
  const priorityRow = (p, i) => `<article class="priority"><div class="priority-index">${String(i + 1).padStart(2, '0')}</div><div><p class="eyebrow dark">${i === 0 ? 'First workstream' : 'Sequenced'}</p><h3>${esc(p.title)}</h3><p class="priority-evidence">${esc(p.evidence)}</p><p>${esc(p.action)}</p><p class="success"><strong>Outcome</strong> ${esc(p.success)}</p>${source(p.source)}</div></article>`
  const delivered = m.delivered.length ? `<div class="delivered"><p class="eyebrow dark">Delivered through the managed security service</p><div class="delivered-grid">${m.delivered.map(d => `<article><h3>${esc(d.title)}</h3><p>${esc(d.outcome)}</p>${source(`${d.reference}. Completed ${d.date}.${d.pillar ? ' ' + d.pillar + '.' : ''}`)}</article>`).join('')}</div></div>` : ''
  // The MFA method update: users still on text message or voice move to a stronger method before Microsoft
  // retires those methods. Never framed as a passwordless programme (Oct 14, 2026).
  const mfaMethods = m.mfaMethods && m.mfaMethods.retiring > 0 ? `<div class="mfa-methods"><div><p class="eyebrow">Identity · MFA method update</p><h3>${fmt(m.mfaMethods.retiring)} of your users signed in with text message or voice over the last 30 days. Atmosera recommends moving each one to a passkey well ahead of ${esc(m.mfaMethods.deadline)}.</h3><p>${esc(m.mfaMethods.timeline)} ${esc(m.mfaMethods.reliance)}${m.mfaMethods.authenticator > 0 ? ` ${fmt(m.mfaMethods.authenticator)} ${m.mfaMethods.authenticator === 1 ? 'user' : 'users'} signed in with the Microsoft Authenticator app or an OTP token.` : ''}${m.mfaMethods.resistant > 0 ? ` ${fmt(m.mfaMethods.resistant)} ${m.mfaMethods.resistant === 1 ? 'user already signs' : 'users already sign'} in with a phishing-resistant method.` : ''}</p>${source(m.mfaMethods.source)}</div><ol class="steps">${m.mfaMethods.steps.map(([head, body], i) => `<li><span>${i + 1}</span><div><strong>${esc(head)}</strong>${esc(body)}</div></li>`).join('')}</ol><p class="success"><strong>Outcome</strong> ${esc(m.mfaMethods.outcome)}</p></div>` : ''
  const roadmap = `<section class="page" id="roadmap">${heading('05', m.delivered.length ? 'Delivered and sequenced' : 'What comes next', 'The hardening sequence that follows, grouped by the outcome each item moves')}
    <div class="page-body"><p class="section-scope">Priorities reflect the evidence collected ${esc(m.readDate)}. Atmosera recommends staging each enforcement in an audit or report-only mode where the control supports one, reviewing it with your team, then turning it on.</p>${delivered}
    <div class="priorities">${m.priorities.slice(0, 3).map(priorityRow).join('')}</div>
    ${m.priorities.length > 3 ? `<details class="additional"><summary>Also sequenced (${m.priorities.length - 3})</summary>${m.priorities.slice(3).map((p, i) => priorityRow(p, i + 3)).join('')}</details>` : ''}
    <div class="stages"><div><span>01</span><h3>Confirm</h3><p>Validate affected workloads, business impact and the intended control scope.</p></div><div><span>02</span><h3>Pilot</h3><p>Stage approved changes in report-only mode with the client team and document exceptions.</p></div><div><span>03</span><h3>Verify</h3><p>Recollect the evidence and confirm the outcome at the next review.</p></div></div>
    ${mfaMethods}
    <div class="decision-note"><h3>How this order is proposed</h3><p>Every item on this board comes from a reading in the collected evidence. The order is a recommendation for agreement at this review: the highest-priority items go first through your change control process, with the remainder behind them in deliberate order.</p></div>
    </div>${footer('05', 'Roadmap')}</section>`

  // 06 Posture in context
  // Each score reads as a percentage with its movement in percentage points from the starting reading, never as
  // points available (Oct 14, 2026).
  const cloudCard = m.cloudScore ? `<article class="score-card"><p class="eyebrow">Defender for Cloud · Your Azure resource estate</p><div class="score-main">${ring(m.cloudScore.value, `Defender for Cloud score ${pctText(m.cloudScore.value)}`)}<div><h3>${esc(pctText(m.cloudScore.value))}</h3><p>${esc(m.cloudScore.note)}${m.posture.assessed !== null ? ` Measured across ${fmt(m.posture.assessed)} assessed resources.` : ''}</p>${m.cloudScore.delta && m.cloudScore.delta.points > 0 ? `<p class="up">Up ${fmt(m.cloudScore.delta.points)} points since ${esc(m.cloudScore.delta.since)}, from ${esc(pctText(m.cloudScore.delta.from))}</p>` : '<p class="small">Reported as current state.</p>'}</div></div>${sparkline(m.cloudScore.trend, 'Defender for Cloud score by month')}${source(m.cloudScore.source)}</article>` : '<article class="score-card"><p class="eyebrow">Defender for Cloud</p><h3>Reading completed in the review</h3></article>'
  const tenantCard = m.tenantScore ? `<article class="score-card"><p class="eyebrow">Microsoft Secure Score · Your Microsoft 365 tenant</p><div class="score-main">${ring(m.tenantScore.value, `Tenant Secure Score ${pctText(m.tenantScore.value)}`)}<div><h3>${esc(pctText(m.tenantScore.value))}</h3><p>${esc(m.tenantScore.note)}</p>${m.tenantScore.delta ? `<p class="up">Up ${fmt(m.tenantScore.delta.points)} points since ${esc(m.tenantScore.delta.since)}, from ${esc(pctText(m.tenantScore.delta.from))}</p>` : ''}</div></div>${m.tenantScore.categories.length ? `<div class="categories">${m.tenantScore.categories.map(c => `<div><span>${esc(c.label)}</span>${bar(c.pct, `${c.label} ${pctText(c.pct)}`)}<strong>${esc(pctText(c.pct))}</strong></div>`).join('')}</div>` : ''}${source(m.tenantScore.source)}</article>` : '<article class="score-card muted"><p class="eyebrow">Microsoft Secure Score · Your Microsoft 365 tenant</p><h3>Added from the portal reading</h3><p class="small">The tenant score is read in the Defender portal and added through the review context so both estates are presented together.</p></article>'
  const meters = [m.posture.highHealthy ? { label: 'High severity assessments healthy', value: `${fmt(m.posture.highHealthy.good)} of ${fmt(m.posture.highHealthy.total)}`, pct: m.posture.highHealthy.pct, source: m.posture.highHealthy.source } : null, m.posture.benchmark ? { label: 'Microsoft cloud security benchmark controls passed', value: `${fmt(m.posture.benchmark.passed)} of ${fmt(m.posture.benchmark.total)}`, pct: m.posture.benchmark.pct, source: m.posture.benchmark.source } : null].filter(Boolean)
  const scoreControls = m.posture.scoreControls.length ? `<h3>Where the next points are</h3><p class="small">Microsoft score controls ranked by the points still available. ${esc(m.posture.scoreControlBasis)}</p><div class="score-controls">${m.posture.scoreControls.slice(0, 10).map(c => `<div><div><h4>${esc(c.label)}</h4>${c.resources ? `<p class="small">${fmt(c.healthy)} of ${fmt(c.resources)} ${c.resources === 1 ? 'resource' : 'resources'} healthy</p>` : ''}</div>${bar(c.pct, `${c.label}: ${pctText(c.pct)}`)}<strong>${esc(pctText(c.pct))}</strong><span>${fmt(c.remaining)} ${c.remaining === 1 ? 'point' : 'points'} available</span></div>`).join('')}</div>${source(m.posture.scoreControlSource)}` : ''
  const posture = `<section class="page detailed-only" id="posture">${heading('06', 'Tenant and cloud security posture', 'Microsoft calculates both of these scores. We report them as benchmark and context, and we do not manage the environment to them.')}
    <div class="page-body"><div class="two-col even">${cloudCard}${tenantCard}</div>
    ${meters.length ? `<div class="meters">${meters.map(x => `<div class="meter"><div class="meter-head"><h4>${esc(x.label)}</h4><strong>${esc(x.value)}</strong></div>${bar(x.pct, `${x.label}: ${x.value}`)}<span class="small">${esc(pctText(x.pct))}</span>${source(x.source)}</div>`).join('')}</div>` : ''}
    ${scoreControls}
    <div class="explainer"><p class="eyebrow dark">Microsoft changed how Secure Score is calculated</p><p>A score movement can reflect a change in the measurement model, the scope or the weighting rather than a change in your controls. Through 2026 Microsoft widened what counts as an assessed resource, restated history when Defender for Cloud moved into the Defender portal, and began counting nested findings individually. The denominator, the weighting and the evaluated scope can all move the percentage while the underlying configuration has not changed. We track the controls behind the score, not the percentage alone.</p></div>
    <div class="inventory"><div><span class="big-number">${fmt(m.posture.estate)}</span><h3>Azure resources in the estate</h3><p class="small">${m.excluded ? `Managed resource groups matching ${esc(m.excluded)} are excluded.` : 'No managed resource group exclusion was configured.'}</p></div><div><span class="big-number">${fmt(m.posture.assessed)}</span><h3>Resources assessed by Defender for Cloud</h3><p class="small">Distinct resources in assessment records at collection.</p></div><div><span class="big-number">${m.posture.rules ? fmt(m.posture.rules.enabled) : fmt(m.posture.telemetryTables)}</span><h3>${m.posture.rules ? 'Analytics rules active in Sentinel' : 'Telemetry tables collected'}</h3><p class="small">${m.posture.rules ? `Of ${fmt(m.posture.rules.total)} rules across ${m.workspaces.length} ${m.workspaces.length === 1 ? 'workspace' : 'workspaces'}.` : 'Distinct data types reaching the workspaces.'}</p></div></div>
    <h3>Sentinel collection scope</h3><div class="table-scroll"><table><thead><tr><th scope="col">Workspace</th><th scope="col">Retention</th></tr></thead><tbody>${m.workspaces.map(w => `<tr><td>${esc(w.Name)}</td><td>${fmt(w.RetentionDays)} days</td></tr>`).join('')}</tbody></table></div><p class="small">Tenant-wide sign-in readings use ${esc(m.tenantWorkspace)}. Alert metrics come from one combined query across the workspaces. Workspace medians and distinct counts are never added together.</p>
    </div>${footer('06', 'Posture in context')}</section>`

  report.innerHTML = summary + outcomes + measured + controls + roadmap + posture
  document.title = `${m.client} | Security business review`

  const depth = document.getElementById('depth')
  depth.value = m.depth
  function setDepth() {
    document.body.dataset.depth = depth.value
    document.querySelectorAll('.additional, .data-details').forEach(d => { d.open = depth.value === 'detailed' })
  }
  depth.addEventListener('change', setDepth)
  setDepth()
  document.getElementById('print').addEventListener('click', () => window.print())
})()
