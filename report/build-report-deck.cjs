/* PowerPoint edition of the CyberSOC monthly security report (03-security-report.pptx), written by
   New-CyberSocReport.ps1 beside the HTML. The CyberSOC slides (the month at a glance, the 90-day trend, threat
   intelligence and vulnerability management) come from report/cybersoc-model.js, the rest from the EBR deck it was
   copied from. It reads the same embedded data and runs the same report
   model, then the story layer (report-story.js) for the wins, decisions, drift and roadmap.

   Structure (docs/plans/2026-10-12-ebr-deck-restructure-design.md, grounding slides added Oct 14, 2026):
   cover, executive summary (the outcome KPIs, the four tier "How we report posture" block as the HTML
   executive summary shows it, then wins, watch and the items that need action), wins, security operations,
   confirmed threats (whenever the pack has true positives, with the examples table when titles can be shown,
   then the outcome cards and the handling strip when the table leaves room), control posture, measured outcomes by pillar, hardening roadmap, priority workstreams, the
   MFA method update, decisions needed, then the appendix: the control register, scope and evidence. Brief
   keeps the cover, summary, wins, roadmap, the MFA method update and decisions. Detailed adds the two
   Microsoft score slides to the appendix.

   One MFA gap: when MFA at sign-in and MFA at the admin portals both read below E, every slide outside the
   appendix names the gap once, with the admin portal reading folded into its figure line.

   A foundational control below E is a gap against the baseline. The deck never says it was configured at
   build, drifted or regressed, because the evidence holds the current reading only.

   Speaker notes are talking points built only from text the client already sees in the HTML. The
   presenter notes (open alert counts, severity increases, automation share, the evidence review) are
   never copied in, so the deck is safe to send to the client after the review.

   Usage: node report/build-report-deck.cjs <data.json> <output.pptx> */
'use strict'
const fs = require('node:fs')
const path = require('node:path')
const { createDeck, writeDeck, lines, HEX, X0, CW } = require('./deck-common.cjs')
const { build, fmt, clean, pctText, plural, RETIREMENT, smallSampleText, duration, date } = require('./report-model.js')
const { buildStory, shortName } = require('./report-story.js')
const CyberSoc = require('./cybersoc-model.js')

const [dataFile, outFile] = process.argv.slice(2)
if (!dataFile || !outFile) { console.error('usage: node build-report-deck.cjs <data.json> <output.pptx>'); process.exit(2) }
const data = JSON.parse(fs.readFileSync(dataFile, 'utf8').replace(/^﻿/, ''))
const m = build(data)
const st = buildStory(m, data)
const cs = CyberSoc.build(data, m)

const TOP = 1.75, BOTTOM = 7.0
const balanced = m.depth !== 'brief', detailed = m.depth === 'detailed'
const notesOf = parts => parts.flat(3).map(clean).filter(Boolean).join('\n\n')
const sentence = t => { const v = clean(t); return v ? v.charAt(0).toUpperCase() + v.slice(1) : '' }
const list = items => items.length <= 1 ? items.join('') : `${items.slice(0, -1).join(', ')} and ${items[items.length - 1]}`
const scopeMeta = `Posture read ${m.readDate} · ${plural(m.subscriptions, 'subscription', 'subscriptions')} · ${plural(m.workspaces.length, 'Sentinel workspace', 'Sentinel workspaces')}`

async function main() {
  const { pres, C, card, chip, text, meter, markFill, rule, glue } = createDeck({ title: `${m.client} | CyberSOC monthly security report, ${cs.month.label}` })
  const content = (section, title, subtitle) => {
    const s = pres.addSlide({ masterName: 'Atmosera Content', sectionTitle: section })
    s.addText(title, { placeholder: 'title' })
    if (subtitle) s.addText(subtitle, { placeholder: 'subtitle' })
    return s
  }
  const eyebrow = (s, label, x, y, w, color = C.text2, name = label) => text(s, label.toUpperCase(), { x, y, w, h: 0.3, fontSize: 12, bold: true, color, charSpacing: 1.5, objectName: `${name} heading` })
  const emptyCard = (s, message, name, y = TOP, h = 1.2) => { card(s, X0, y, CW, h, name); text(s, message, { x: X0 + 0.4, y: y + 0.3, w: CW - 0.8, h: h - 0.6, fontSize: 16, color: C.text1, valign: 'middle', objectName: `${name} text` }) }
  // A mark chip: E, P or N filled, a dash for not gathered, N/A for no evidence either way.
  const markChip = (s, mark, x, y, w, h, size, name) => {
    if (['E', 'P', 'N'].includes(mark)) return chip(s, mark, x, y, w, h, markFill(mark), size, name)
    s.addShape(pres.shapes.ROUNDED_RECTANGLE, { x, y, w, h, fill: { color: C.background2 }, line: { color: HEX.track, width: 0.5 }, rectRadius: 0.04, objectName: name })
    text(s, mark, { x, y, w, h, fontSize: mark === 'N/A' ? size - 4 : size, bold: true, color: C.accent6, align: 'center', valign: 'middle', objectName: `${name} text` })
  }
  // Table cells draw only a bottom rule.
  const border = pt => [{ type: 'none' }, { type: 'none' }, { pt, color: HEX.track }, { type: 'none' }]
  // The CyberSOC slides share a KPI row like the executive summary's and a plain table in the deck's style.
  const kpiRow = (sl, tiles, y, name) => {
    if (!tiles.length) return y
    const n = tiles.length, w = CW / n, kw = w - 0.45
    const kpiH = Math.max(1.1, ...tiles.map(k => 0.5 + lines(k.label, kw, 12, true) * 0.2 + lines(k.sub, kw, 10.5) * 0.175 + 0.14))
    rule(sl, X0, y - 0.05, CW, C.text2, 1, `${name} top rule`)
    tiles.forEach((k, i) => {
      const x = X0 + i * w
      if (i) sl.addShape(pres.shapes.LINE, { x, y: y + 0.05, w: 0, h: kpiH - 0.15, line: { color: HEX.track, width: 0.75 }, objectName: `${name} divider ${i}` })
      text(sl, [{ text: k.value, options: { fontSize: 28, bold: true, color: C.accent2, breakLine: true } }, { text: k.label, options: { fontSize: 12, bold: true, color: C.text2, breakLine: true, paraSpaceBefore: 2 } }, { text: k.sub, options: { fontSize: 10.5, color: C.accent6, paraSpaceBefore: 2 } }], { x: x + (i ? 0.3 : 0), y: y + 0.05, w: kw, h: kpiH - 0.1, objectName: `${name} ${i + 1}` })
    })
    rule(sl, X0, y + kpiH, CW, HEX.track, 0.75, `${name} bottom rule`)
    return y + kpiH + 0.2
  }
  const HEAD_ROW = 0.36
  const deckTable = (sl, head, body, { x, y, w, colW, name, size = 11, rowH = 0.27, numeric = [] }) => {
    const cell = (t, i, o = {}) => ({ text: glue(String(t)), options: { fontSize: size, color: HEX.dk1, align: numeric.includes(i) ? 'right' : 'left', valign: 'middle', border: border(0.5), ...o } })
    const rows = [head.map((t, i) => cell(t, i, { fontSize: size - 1, color: HEX.accent6, valign: 'bottom', border: border(0.75) })), ...body.map(r => r.map((t, i) => cell(t, i, i ? {} : { bold: true, color: HEX.dk2 })))]
    sl.addTable(rows, { x, y, w, colW, rowH: [HEAD_ROW, ...body.map(() => rowH)], margin: [0.03, 0.08, 0.03, 0.08], objectName: name })
    return y + HEAD_ROW + rowH * body.length
  }
  const caption = (sl, value, x, y, w, name, size = 10) => { const t = glue(clean(value)); const h = lines(t, w - 0.1, size) * 0.17 + 0.05; text(sl, t, { x, y, w, h, fontSize: size, color: C.accent6, objectName: name }); return y + h }
  const periodWord = cs.months.length === 3 ? 'the 90 days' : 'the period'
  const reportIndex = cs.months.findIndex(x => x.report)
  const prevMonth = reportIndex > 0 ? cs.months[reportIndex - 1] : null

  // 1. Cover
  pres.addSection({ title: 'Summary' })
  let s = pres.addSlide({ masterName: 'Atmosera Title', sectionTitle: 'Summary' })
  s.addText('MANAGED SECURITY SERVICES · CYBERSOC MONTHLY REPORT', { placeholder: 'eyebrow' })
  s.addText('CyberSOC monthly security report', { placeholder: 'title' })
  s.addText(m.client, { placeholder: 'subtitle' })
  s.addText(glue(`${cs.month.label} · 90-day trend ${m.period.label}`), { placeholder: 'caption' })
  s.addText(scopeMeta, { placeholder: 'meta' })
  s.addNotes(notesOf([`CyberSOC monthly security report for ${m.client}, ${cs.month.label}.`, `Alert activity covers ${m.period.label}, the report month with the 90-day trend. Identity and endpoint readings use the source lookback, generally the last 30 days. Configuration and score readings are from ${m.readDate}.`]))

  // 1b. The month at a glance: the CyberSOC tiles, then the report month beside the months before it with a neutral
  // change, as the HTML executive summary shows them.
  const nowOps = reportIndex >= 0 ? cs.ops.monthly[reportIndex] : null
  s = content('Summary', `${cs.month.label} at a glance`, nowOps ? `${plural(nowOps.total, 'alert', 'alerts')} created in ${cs.month.label}${prevMonth && cs.ops.monthly[reportIndex - 1] ? `, against ${fmt(cs.ops.monthly[reportIndex - 1].total)} in ${prevMonth.name}` : ''}` : `The report month with the 90-day trend`)
  let gy = kpiRow(s, cs.headline, TOP, 'Month KPI')
  if (cs.glance.rows.length) {
    const fits = Math.max(1, Math.floor((BOTTOM - gy - 0.45 - HEAD_ROW) / 0.27)), rowsShown = cs.glance.rows.slice(0, fits)
    const monthW = 1.45, changeW = prevMonth ? 2.6 : 0, labelW = CW - monthW * cs.months.length - changeW
    gy = deckTable(s, ['Measure', ...cs.glance.months, ...(prevMonth ? [`Change from ${prevMonth.label}`] : [])], rowsShown.map(r => [r.label, ...r.values, ...(prevMonth ? [r.change] : [])]), { x: X0, y: gy, w: CW, colW: [labelW, ...cs.months.map(() => monthW), ...(prevMonth ? [changeW] : [])], name: 'Month at a glance table', numeric: cs.months.map((_, i) => i + 1) })
    caption(s, `Evidence ${[...new Set(rowsShown.map(r => r.source))].join(', ')}. The change column compares with the previous month and makes no judgment.`, X0, gy + 0.08, CW, 'Month at a glance caption')
  } else emptyCard(s, 'The monthly readings are completed in the review.', 'Month at a glance', gy)
  s.addNotes(notesOf([cs.summary, cs.highlights.map(h => `${h.title}. ${h.summary}`), 'The month at a glance puts the report month beside the months before it. The change column makes no judgment: more alerts can mean more coverage as well as more activity.']))

  // 2. Executive summary, in line with the HTML executive summary page: the outcome KPIs, the four tier
  // "How we report posture" block, then the wins, the watch list and the items that need action from the
  // client (Oct 14, 2026). Every block takes the height its text needs, so nothing overlaps.
  s = content('Summary', 'Executive summary', st.takeaways.summary)
  let sy = TOP
  if (st.kpis.length) {
    const n = st.kpis.length, w = CW / n, kw = w - 0.45
    const kpiH = Math.max(1.2, ...st.kpis.map(k => 0.5 + lines(k.label, kw, 12, true) * 0.2 + lines(k.sub, kw, 10.5) * 0.175 + 0.14))
    rule(s, X0, TOP - 0.05, CW, C.text2, 1, 'KPI top rule')
    st.kpis.forEach((k, i) => {
      const x = X0 + i * w
      if (i) s.addShape(pres.shapes.LINE, { x, y: TOP + 0.05, w: 0, h: kpiH - 0.15, line: { color: HEX.track, width: 0.75 }, objectName: `KPI divider ${i}` })
      text(s, [{ text: k.value, options: { fontSize: 30, bold: true, color: C.accent2, breakLine: true } }, { text: k.label, options: { fontSize: 12, bold: true, color: C.text2, breakLine: true, paraSpaceBefore: 2 } }, { text: k.sub, options: { fontSize: 10.5, color: C.accent6, paraSpaceBefore: 2 } }], { x: x + (i ? 0.3 : 0), y: TOP + 0.05, w: kw, h: kpiH - 0.1, objectName: `KPI ${i + 1}` })
    })
    rule(s, X0, TOP + kpiH, CW, HEX.track, 0.75, 'KPI bottom rule')
    sy = TOP + kpiH + 0.15
  }
  // How we report posture: the four tiers of the HTML executive summary on a navy band, up to three rows each.
  // Long row labels are shortened for the band. The HTML keeps the full label.
  const TIER_SHORT = [
    [/^Confirmed threats$/, 'Confirmed threats'],
    [/^Median time to close, high severity alerts$/, 'Median close, high severity'], [/^Median time to close, all alerts$/, 'Median close, all alerts'],
    [/^90th percentile close/, 'Nine in ten closed within'], [/^Detections correlated into alerts$/, 'Detections correlated'],
    [/^Foundational controls enforced$/, 'Foundational controls'], [/^Defense in depth controls enforced$/, 'Defense in depth controls'],
    [/^Critical exploitable findings open$/, 'Critical exploitable findings'], [/^Members who signed in without MFA, last 30 days$/, 'Members without MFA'], [/^Evaluated members without MFA, last 30 days$/, 'Evaluated members without MFA'], [/^Users on a retiring MFA method$/, 'Users on SMS or voice MFA'],
    [/^Azure virtual machines pending endpoint onboarding$/, 'VMs not on endpoint detection'], [/^Storage accounts open to public networks$/, 'Public storage accounts'], [/^Key Vaults without purge protection$/, 'Vaults without purge protection'],
    [/^Virtual machines pending host encryption$/, 'VMs pending host encryption'], [/^Resources without diagnostic logging$/, 'Resources not logging'], [/^AI service resources without workload protection$/, 'AI resources without protection'],
    [/^Workload subnets without segmentation$/, 'Subnets without segmentation'], [/^Virtual machines without Azure Backup$/, 'VMs without Azure Backup'],
    [/^Microsoft tenant Secure Score$/, 'Tenant Secure Score'], [/^High severity assessments healthy$/, 'High severity findings healthy'], [/^Resources assessed by Defender for Cloud$/, 'Resources assessed']
  ]
  const tierLabel = r => { const hit = TIER_SHORT.find(([re]) => re.test(r.label)); if (hit) return hit[1]; return /^TIER\./.test(r.id) ? r.label : sentence(shortName(r)) }
  const tierDefs = [['outcomes', 'Tier 1 · Outcomes', 'Did the program hold'], ['controls', 'Tier 2 · Control effectiveness', 'What is actually enforced'], ['hardening', 'Tier 3 · Hardening next', 'Proposed in priority order'], ['benchmark', 'Tier 4 · Vendor benchmark', 'Context, not the objective']]
  const tierPad = 0.25, tierGap = 0.3, tierW = (CW - 2 * tierPad - 3 * tierGap) / 4, tierValueW = 0.8, tierLabelW = tierW - tierValueW - 0.05
  // A tier count that holds a control on a small sample names it beside the label, as the HTML does (issue #24).
  const tierRows = tierDefs.map(([key]) => m.tiers[key].slice(0, 3).map(r => ({ ...r, short: `${tierLabel(r)}${r.note ? ` (${r.note})` : ''}` })))
  const tierRowH = r => Math.min(2, lines(r.short, tierLabelW, 9)) * 0.16 + 0.09
  const tierBodyH = Math.max(0.27, ...tierRows.map(rows => rows.reduce((n, r) => n + tierRowH(r), 0)))
  const tierH = 0.42 + 0.48 + tierBodyH + 0.12
  card(s, X0, sy, CW, tierH, 'Posture tiers card', C.text2)
  text(s, 'HOW WE REPORT POSTURE', { x: X0 + tierPad, y: sy + 0.13, w: 3.0, h: 0.24, fontSize: 10, bold: true, color: C.accent1, charSpacing: 1.5, objectName: 'Posture tiers heading' })
  text(s, 'Reported for the whole tenant, never as a single vendor percentage, and weighted in this order.', { x: X0 + 3.3, y: sy + 0.13, w: CW - 3.3 - tierPad, h: 0.24, fontSize: 10, color: C.background2, align: 'right', objectName: 'Posture tiers note' })
  tierDefs.forEach(([key, eye, title], i) => {
    const x = X0 + tierPad + i * (tierW + tierGap), ty = sy + 0.42
    if (i) s.addShape(pres.shapes.LINE, { x: x - tierGap / 2, y: ty, w: 0, h: tierH - 0.54, line: { color: HEX.accent5, width: 0.75 }, objectName: `Tier ${i + 1} divider` })
    text(s, [{ text: eye.toUpperCase(), options: { fontSize: 8.5, bold: true, color: C.accent1, charSpacing: 1, breakLine: true } }, { text: title, options: { fontSize: 11, bold: true, color: C.background1, paraSpaceBefore: 2 } }], { x, y: ty, w: tierW, h: 0.46, objectName: `Tier ${i + 1} head` })
    let ry = ty + 0.48
    if (!tierRows[i].length) text(s, key === 'hardening' ? 'No open hardening items from this collection.' : 'Readings are completed in the review.', { x, y: ry, w: tierW, h: 0.3, fontSize: 9.5, color: C.background2, objectName: `Tier ${i + 1} empty` })
    tierRows[i].forEach((r, n) => {
      const h = tierRowH(r)
      rule(s, x, ry, tierW, HEX.accent5, 0.5, `Tier ${i + 1} row ${n + 1} rule`)
      text(s, r.short, { x, y: ry + 0.03, w: tierLabelW, h: h - 0.03, fontSize: 9, color: C.background2, valign: 'middle', objectName: `Tier ${i + 1} row ${n + 1} label` })
      text(s, r.value, { x: x + tierW - tierValueW, y: ry + 0.03, w: tierValueW, h: h - 0.03, fontSize: 9.5, bold: true, color: key === 'hardening' ? C.accent4 : C.background1, align: 'right', valign: 'middle', objectName: `Tier ${i + 1} row ${n + 1} value` })
      ry += h
    })
  })
  sy += tierH + 0.15
  // Wins, the watch list and the items that need action. Each item is one paragraph, the figure leading, so the
  // column takes the height its text needs. Items that would run past the slide are left out.
  const colW = (CW - 0.8) / 3, colRoom = BOTTOM - sy - 0.5
  ;[['Wins', C.accent3, st.summaryWins, 'Readings are completed in the review.'], ['Watch', C.accent4, st.watch, 'Nothing on the watch list from this collection.'], ['Items that need action', C.text2, st.summaryAsks, 'Nothing needs action from your team before the next review.']].forEach(([label, color, items, empty], i) => {
    const x = X0 + i * (colW + 0.4)
    eyebrow(s, label, x, sy, colW, C.text2, `Summary ${label}`)
    rule(s, x, sy + 0.36, colW, color, 2.5, `Summary ${label} rule`)
    if (!items.length) { text(s, empty, { x, y: sy + 0.5, w: colW, h: 0.5, fontSize: 12, color: C.accent6, objectName: `Summary ${label} empty` }); return }
    const fit = [], runs = []
    let used = 0
    for (const it of items) {
      const need = lines(`${it.value} ${it.label}`, colW, 11) * 0.19 + (fit.length ? 0.1 : 0)
      if (used + need > colRoom) break
      fit.push(it); used += need
    }
    fit.forEach((it, n) => runs.push({ text: it.value, options: { fontSize: 12, bold: true, color: C.text2, paraSpaceBefore: n ? 7 : 0 } }, { text: ` ${it.label}`, options: { fontSize: 11, color: C.text1, breakLine: n < fit.length - 1 } }))
    text(s, runs, { x, y: sy + 0.5, w: colW, h: colRoom, objectName: `Summary ${label} items` })
  })
  s.addNotes(notesOf(['Lead with outcomes.', st.takeaways.summary, st.kpis.map(k => `${k.label}: ${k.value}. ${k.sub}.`), 'Posture is reported for the whole tenant, never as a single vendor percentage, in four tiers: outcomes, control effectiveness, what we are hardening next, and the vendor benchmark as context.', 'Then the wins, the watch list, and the items that need action from your team before the next review.']))

  // The threat intelligence and vulnerability management slides, at every depth: after the operations slides in
  // Balanced and Detailed, before the roadmap in Brief.
  function cyberSocSlides(section) {
    const ti = cs.threat, vk = cs.vuln
    s = content(section, 'Threat intelligence', ti.matches ? `${plural(ti.matches.month, 'threat intelligence match', 'threat intelligence matches')} in ${cs.month.label}, ${fmt(ti.matches.total)} over ${periodWord}` : `The threats observed in your environment over ${periodWord}`)
    let y = kpiRow(s, ti.tiles, TOP, 'Threat KPI')
    const lw = CW * 0.5, rx = X0 + lw + 0.4, rw = CW - lw - 0.4
    eyebrow(s, 'MITRE ATT&CK tactics on the alerts', X0, y, lw, C.text2, 'Alert tactics')
    if (ti.stages && ti.stages.rows.length) {
      const rowsShown = ti.stages.rows.slice(0, 9)
      s.addChart(pres.charts.BAR, [{ name: 'Alerts', labels: rowsShown.map(t => t.label), values: rowsShown.map(t => t.alerts) }], {
        x: X0 - 0.1, y: y + 0.3, w: lw + 0.1, h: BOTTOM - y - 0.85, barDir: 'bar', chartColors: [HEX.accent2], barGapWidthPct: 40,
        showValue: true, dataLabelPosition: 'outEnd', dataLabelColor: HEX.dk2, dataLabelFontSize: 11, dataLabelFontBold: true, dataLabelFontFace: '+mn-lt', dataLabelFormatCode: '#,##0',
        catAxisOrientation: 'maxMin', catAxisLabelColor: HEX.dk1, catAxisLabelFontSize: 11, catAxisLabelFontFace: '+mn-lt', valAxisHidden: true,
        valGridLine: { style: 'none' }, catGridLine: { style: 'none' }, showLegend: false, objectName: 'Alert tactics chart'
      })
      caption(s, 'MITRE ATT&CK tactics recorded on the detections in the alerts, in attack chain order. A tactic is a label recorded at detection, not an investigation finding.', X0, BOTTOM - 0.5, lw, 'Alert tactics caption')
    } else text(s, 'The tactics on the alerts are confirmed in the review.', { x: X0, y: y + 0.4, w: lw, h: 0.4, fontSize: 13, color: C.accent6, objectName: 'Alert tactics empty' })
    let ry = y
    if (ti.matches) {
      eyebrow(s, 'Threat intelligence matches', rx, ry, rw, C.text2, 'Threat matches')
      ry = deckTable(s, ['Month', 'Matches', 'In ticketed alerts'], ti.matches.byMonth.map(x => [x.label, fmt(x.total), fmt(x.ticketed)]), { x: rx, y: ry + 0.35, w: rw, colW: [rw * 0.4, rw * 0.25, rw * 0.35], name: 'Threat matches table', numeric: [1, 2] })
      ry = caption(s, 'A match is a known indicator observed in your telemetry, not an investigation finding.', rx, ry + 0.05, rw, 'Threat matches caption') + 0.1
    }
    if (vk.mode === 'runs' && vk.kevKnown && ry < BOTTOM - 1.2) {
      eyebrow(s, 'Known exploited vulnerabilities present', rx, ry, rw, C.text2, 'KEV')
      const room = Math.max(1, Math.floor((BOTTOM - ry - 0.8 - HEAD_ROW) / 0.27))
      if (vk.kev.length) ry = deckTable(s, ['Product', 'VMs', 'Added to CISA KEV'], vk.kev.slice(0, Math.min(4, room)).map(k => [k.product, fmt(k.vms), `${k.added}${k.thisMonth ? ' (this month)' : ''}`]), { x: rx, y: ry + 0.35, w: rw, colW: [rw * 0.42, rw * 0.13, rw * 0.45], name: 'KEV table', numeric: [1] })
      else ry = caption(s, 'No open finding carries a CVE CISA lists as known exploited.', rx, ry + 0.4, rw, 'KEV empty', 12)
      caption(s, 'A CISA KEV listing means exploitation in the wild, not in your environment.', rx, ry + 0.05, rw, 'KEV caption')
    } else if (ti.identity && ry < BOTTOM - 1.4) {
      eyebrow(s, 'Identity threat activity', rx, ry, rw, C.text2, 'Identity')
      deckTable(s, ['Measure', ...ti.identity.byMonth.map(x => x.label)], [['Failed password sign-ins', 'failedPassword'], ['Password spraying sources', 'sprayIps'], ['Blocked by Conditional Access', 'blocked']].map(([label, f]) => [label, ...ti.identity.byMonth.map(x => fmt(x[f]))]), { x: rx, y: ry + 0.35, w: rw, colW: [rw * 0.46, ...ti.identity.byMonth.map(() => rw * 0.54 / ti.identity.byMonth.length)], name: 'Identity table', numeric: ti.identity.byMonth.map((_, i) => i + 1) })
    }
    s.addNotes(notesOf([
      ti.tiles.map(t => `${t.label}: ${t.value}. ${t.sub}`),
      ti.stages ? `Tactics on the alerts over ${periodWord}: ${ti.stages.rows.map(t => `${t.label} ${fmt(t.alerts)}`).join(', ')}.` : '',
      ti.techniques && ti.techniques.rows.length ? `Most frequent techniques: ${ti.techniques.rows.slice(0, 5).map(t => t.label).join(', ')}.` : '',
      ti.identity && reportIndex >= 0 ? `Identity threat activity in ${cs.month.label}: ${fmt(ti.identity.byMonth[reportIndex].failedPassword)} failed password sign-ins and ${fmt(ti.identity.byMonth[reportIndex].sprayIps)} password spraying sources. A password spraying source is a signal, not a confirmed attack.` : '',
      ti.unmeasured.length ? `Completed in the review: ${ti.unmeasured.map(u => u.label.toLowerCase()).join(', ')}.` : '',
      'Threat intelligence matches and the tactics on the alerts describe what the detections recorded, not investigation findings. A CISA KEV listing means CISA has reported exploitation in the wild, not exploitation in your environment.'
    ]))

    s = content(section, 'Vulnerability management', vk.mode === 'runs' && vk.latest ? `${plural(vk.latest.open, 'open finding', 'open findings')} at the assessment of ${vk.latest.label}${vk.latest.kev !== null ? `, ${fmt(vk.latest.kev)} with a CISA KEV-listed CVE` : ''}` : vk.mode === 'defender' ? 'The vulnerabilities Defender reports open on Azure virtual machines' : 'The vulnerability position is completed in the review')
    y = kpiRow(s, vk.tiles, TOP, 'Vulnerability KPI')
    if (vk.mode === 'runs' && vk.latest) {
      eyebrow(s, 'Open findings at each assessment', X0, y, lw, C.text2, 'Assessments')
      const sev = [['Critical', 'critical', HEX.accent4], ['High', 'high', HEX.sevHigh], ['Medium', 'medium', HEX.sevMedium], ['Low', 'low', HEX.sevLow]]
      s.addChart(pres.charts.BAR, sev.map(([name, f]) => ({ name, labels: vk.runs.map(r => r.label), values: vk.runs.map(r => r[f]) })), {
        x: X0 - 0.1, y: y + 0.3, w: lw + 0.1, h: BOTTOM - y - 0.85, barDir: 'col', barGrouping: 'stacked', barGapWidthPct: 70, chartColors: sev.map(x => x[2]),
        catAxisLabelColor: HEX.dk1, catAxisLabelFontSize: 10, catAxisLabelFontFace: '+mn-lt', valAxisLabelColor: HEX.accent6, valAxisLabelFontSize: 10, valAxisLabelFontFace: '+mn-lt',
        valGridLine: { color: HEX.track, size: 0.5 }, catGridLine: { style: 'none' }, showLegend: true, legendPos: 'b', legendFontSize: 10, legendFontFace: '+mn-lt', legendColor: HEX.dk1, objectName: 'Assessments chart'
      })
      caption(s, vk.change && vk.change.compared ? `Since ${date(vk.change.from)}: ${fmt(vk.change.openNew)} new, ${fmt(vk.change.openGone)} no longer open, pending validation.` : 'Assessments are compared only when both are complete.', X0, BOTTOM - 0.5, lw, 'Assessments caption')
      eyebrow(s, 'Top products to patch', rx, y, rw, C.text2, 'Top products')
      const room = Math.max(1, Math.floor((BOTTOM - y - 0.85 - HEAD_ROW) / 0.3))
      const top = vk.top.slice(0, Math.min(6, room))
      const end = top.length ? deckTable(s, ['Product', 'VMs', 'Exploit intelligence', 'Owner'], top.map(t => [t.product, fmt(t.vms), t.kev ? 'CISA KEV listed' : t.exploit ? 'Public exploit code' : 'None reported', t.owner]), { x: rx, y: y + 0.35, w: rw, colW: [rw * 0.36, rw * 0.1, rw * 0.28, rw * 0.26], name: 'Top products table', size: 10.5, rowH: 0.3, numeric: [1] }) : y + 0.4
      caption(s, `Remediation status: ${vk.statuses.map(x => `${x.label.toLowerCase()} ${fmt(x.n)}`).join(', ') || 'not recorded'}.`, rx, end + 0.08, rw, 'Remediation status caption')
    } else if (vk.mode === 'defender') {
      const D = vk.defender
      eyebrow(s, 'Open CVEs by severity, current state', X0, y, lw, C.text2, 'Defender severity')
      s.addChart(pres.charts.BAR, [{ name: 'CVEs', labels: D.bySeverity.map(x => x.level), values: D.bySeverity.map(x => x.cves) }], {
        x: X0 - 0.1, y: y + 0.3, w: lw + 0.1, h: BOTTOM - y - 0.85, barDir: 'bar', chartColors: [HEX.accent2], barGapWidthPct: 40, showValue: true, dataLabelPosition: 'outEnd', dataLabelColor: HEX.dk2, dataLabelFontSize: 11, dataLabelFontBold: true, dataLabelFormatCode: '#,##0',
        catAxisOrientation: 'maxMin', catAxisLabelColor: HEX.dk1, catAxisLabelFontSize: 11, valAxisHidden: true, valGridLine: { style: 'none' }, catGridLine: { style: 'none' }, showLegend: false, objectName: 'Defender severity chart'
      })
      if (D.software.length) {
        eyebrow(s, 'Most exposed software', rx, y, rw, C.text2, 'Software')
        deckTable(s, ['Software', 'Machines', 'CVEs', 'Public exploit'], D.software.slice(0, 6).map(x => [x.name, fmt(x.devices), fmt(x.cves), fmt(x.exploitable)]), { x: rx, y: y + 0.35, w: rw, colW: [rw * 0.46, rw * 0.18, rw * 0.14, rw * 0.22], name: 'Software table', size: 10.5, numeric: [1, 2, 3] })
      }
    } else emptyCard(s, 'The vulnerability position is completed in the review.', 'Vulnerability', y)
    s.addNotes(notesOf([
      vk.tiles.map(t => `${t.label}: ${t.value}. ${t.sub}`),
      vk.mode === 'runs' ? vk.top.slice(0, 5).map(t => `${t.product}, ${t.severity.toLowerCase()}, on ${plural(t.vms, 'virtual machine', 'virtual machines')}. ${t.kev ? 'CISA KEV listed.' : t.exploit ? 'Public exploit code is available.' : ''} Owner ${t.owner.toLowerCase()}.`) : '',
      'A finding is one vulnerable software package on one virtual machine. A finding no longer reported is pending validation until the next assessment confirms it. Public exploit code and a CISA KEV listing do not mean the vulnerability was exploited in your environment.'
    ]))
  }

  // 3. Wins
  s = content('Summary', st.quarter ? 'Quarter wins' : 'Wins this period', st.takeaways.wins)
  if (st.wins.length) {
    const cols = 3, rows = Math.ceil(st.wins.length / cols), w = (CW - 0.6) / 3, h = rows > 1 ? (BOTTOM - TOP - 0.3) / 2 : 2.7
    st.wins.forEach((win, i) => {
      const x = X0 + (i % cols) * (w + 0.3), y = TOP + Math.floor(i / cols) * (h + 0.3)
      card(s, x, y, w, h, `Win ${i + 1} card`)
      rule(s, x, y, w, C.accent1, 2.5, `Win ${i + 1} rule`)
      text(s, [
        { text: win.eyebrow.toUpperCase(), options: { fontSize: 11, bold: true, color: C.accent2, charSpacing: 1.5, breakLine: true } },
        { text: win.value, options: { fontSize: 36, bold: true, color: C.text2, breakLine: true, paraSpaceBefore: 2 } },
        { text: win.label, options: { fontSize: 15, bold: true, color: C.text2, breakLine: true, paraSpaceBefore: 4 } },
        { text: win.sub, options: { fontSize: 12, color: C.accent6, paraSpaceBefore: 6 } }
      ], { x: x + 0.3, y: y + 0.25, w: w - 0.6, h: h - 0.4, objectName: `Win ${i + 1}` })
    })
  } else emptyCard(s, 'Outcome readings are completed in the review.', 'Wins')
  s.addNotes(notesOf(['Each win is traced to collected evidence.', st.wins.map(w => `${w.eyebrow}: ${w.value} ${w.label}. ${w.sub} Evidence ${w.source}`)]))

  if (m.delivered.length) {
    s = content('Summary', 'Delivered this period', 'Completed through the managed security service')
    const items = m.delivered.slice(0, 6), w = (CW - 0.6) / 3, rows = Math.ceil(items.length / 3), h = Math.min(2.5, (BOTTOM - TOP - (rows - 1) * 0.3) / rows)
    items.forEach((d, i) => {
      const x = X0 + (i % 3) * (w + 0.3), y = TOP + Math.floor(i / 3) * (h + 0.3)
      card(s, x, y, w, h, `Delivered ${i + 1} card`)
      text(s, [{ text: d.title, options: { fontSize: 16, bold: true, color: C.text2, breakLine: true } }, { text: d.outcome, options: { fontSize: 13, color: C.text1, paraSpaceBefore: 6, breakLine: true } }, { text: `${d.reference}. Completed ${d.date}.`, options: { fontSize: 11, color: C.accent6, paraSpaceBefore: 6 } }], { x: x + 0.3, y: y + 0.25, w: w - 0.6, h: h - 0.4, objectName: `Delivered ${i + 1}` })
    })
    s.addNotes(notesOf(m.delivered.map(d => `${d.title}. ${d.outcome}`)))
  }

  if (balanced) {
    // 4. Security operations: four quadrants.
    pres.addSection({ title: 'Operations and posture' })
    s = content('Operations and posture', 'Security operations', st.takeaways.operations)
    const qw = (CW - 0.5) / 2, rowTop = [TOP, 4.55], rowH = [2.55, BOTTOM - 4.55]
    const quad = (i, label) => { const x = X0 + (i % 2) * (qw + 0.5), y = rowTop[Math.floor(i / 2)]; rule(s, x, y, qw, C.text2, 1, `${label} rule`); eyebrow(s, label, x, y + 0.12, qw, C.text2, label); return { x, y: y + 0.5, h: rowH[Math.floor(i / 2)] - 0.5 } }
    // Volume by month.
    let q = quad(0, 'Alert volume by month')
    const trendRows = m.trend.slice(-12)
    if (trendRows.length) {
      const sev = ['High', 'Medium', 'Low', 'Informational'].filter(k => k !== 'Informational' || m.trend.some(r => r.Informational > 0))
      const colors = { High: HEX.sevHigh, Medium: HEX.sevMedium, Low: HEX.sevLow, Informational: HEX.sevInfo }
      // Workspace coverage, when it varies across the months shown, sits under the chart, which gives up the height.
      const cov = m.trendCoverage ? `${m.trendCoverage.sentence} ${m.trendCoverage.caption}` : '', covH = cov ? lines(glue(cov), qw - 0.1, 10) * 0.17 + 0.05 : 0
      if (cov) text(s, cov, { x: q.x, y: q.y + q.h - covH, w: qw, h: covH, fontSize: 10, color: C.accent6, objectName: 'Monthly alerts coverage' })
      s.addChart(pres.charts.BAR, sev.map(k => ({ name: k, labels: trendRows.map(r => r.label), values: trendRows.map(r => r[k]) })), {
        x: q.x - 0.1, y: q.y - 0.05, w: qw + 0.1, h: q.h - (cov ? covH + 0.05 : 0), barDir: 'col', barGrouping: 'stacked', barGapWidthPct: trendRows.length > 6 ? 45 : 90,
        chartColors: sev.map(k => colors[k]), catAxisLabelColor: HEX.dk1, catAxisLabelFontSize: 11, catAxisLabelFontFace: '+mn-lt', valAxisLabelColor: HEX.accent6, valAxisLabelFontSize: 10, valAxisLabelFontFace: '+mn-lt',
        valGridLine: { color: HEX.track, size: 0.5 }, catGridLine: { style: 'none' }, showLegend: true, legendPos: 'r', legendFontSize: 11, legendFontFace: '+mn-lt', legendColor: HEX.dk1, objectName: 'Monthly alerts chart'
      })
    } else text(s, 'Monthly volume is confirmed in the review.', { x: q.x, y: q.y, w: qw, h: 0.4, fontSize: 13, color: C.accent6, objectName: 'Monthly alerts empty' })
    // Time to acknowledge and close by severity, every figure shown. A median under 20 minutes or a 90th percentile
    // over one hour carries the uniform caption note. The analyst-handled and automation-closed high severity rows,
    // and the agreed target comparison, go to the speaker notes, as the HTML operations page shows them.
    q = quad(1, 'Time to close, by severity')
    if (m.timing && m.timing.length) {
      const head = ['Severity', 'Closed', 'Median to acknowledge', 'Median to close', '90% closed within'].map((t, i) => ({ text: t, options: { fontSize: 11, color: HEX.accent6, align: i ? 'right' : 'left', valign: 'bottom', border: border(0.75) } }))
      const body = m.timing.map(r => {
        const all = r.scope === 'All', fill = all ? { color: HEX.lt2 } : undefined
        const cell = (t, o = {}) => ({ text: t, options: { fontSize: 13, color: HEX.dk1, align: 'right', fill, border: border(0.5), ...o } })
        return [cell(all ? 'All closed' : r.scope, { bold: true, color: HEX.dk2, align: 'left' }), cell(fmt(r.n)), cell(r.acknowledge ? r.acknowledge.value : '–'), cell(r.median ? r.median.value : '–', { bold: true, color: r.median ? HEX.accent2 : HEX.accent6 }), cell(r.p90 ? r.p90.value : '–')]
      })
      const HEAD_H = 0.42, ROW_H = 0.28, tableH = HEAD_H + ROW_H * body.length
      s.addTable([head, ...body], { x: q.x, y: q.y - 0.05, w: qw, colW: [qw * 0.2, qw * 0.14, qw * 0.24, qw * 0.2, qw * 0.22], rowH: [HEAD_H, ...body.map(() => ROW_H)], margin: [0.03, 0.08, 0.03, 0.08], objectName: 'Time to close table' })
      const captionText = 'Acknowledge is the first status change from New. A median under 20 minutes or a 90th percentile over one hour is covered in the review.'
      const captionY = q.y - 0.05 + tableH + 0.05
      text(s, captionText, { x: q.x, y: captionY, w: qw, h: lines(captionText, qw - 0.1, 10) * 0.17 + 0.05, fontSize: 10, color: C.accent6, objectName: 'Time to close caption' })
    } else text(s, 'Response timing is confirmed in the review.', { x: q.x, y: q.y, w: qw, h: 0.4, fontSize: 13, color: C.accent6, objectName: 'Time to close empty' })
    // How closed alerts were classified. Open alerts appear only as the referral sentence, split by owner only from
    // the reviewed OpenAlertNote record.
    q = quad(2, 'How closed alerts were classified')
    if (m.alerts) {
      const a = m.alerts
      text(s, 'Closed by the SOC', { x: q.x, y: q.y - 0.05, w: qw - 1.2, h: 0.32, fontSize: 15, bold: true, color: C.text2, objectName: 'Closed label' })
      text(s, fmt(a.closed), { x: q.x + qw - 1.2, y: q.y - 0.05, w: 1.2, h: 0.32, fontSize: 15, bold: true, color: C.text2, align: 'right', objectName: 'Closed value' })
      const parts = [['benign', a.benign, HEX.sevLow], ['false positive', a.falsePositives, HEX.sevInfo], ['true positive', a.truePositives, HEX.accent4], ['unclassified', a.unclassified, HEX.track]].filter(([, v]) => v > 0)
      const totalParts = Math.max(1, parts.reduce((n, [, v]) => n + v, 0))
      let bx = q.x
      parts.forEach(([l, v, c]) => { const w = Math.max(0.04, qw * v / totalParts); s.addShape(pres.shapes.RECTANGLE, { x: bx, y: q.y + 0.35, w, h: 0.26, fill: { color: c }, line: { color: c, width: 0 }, objectName: `Closed ${l} bar` }); bx += w })
      // Legend entries wrap to a second line rather than run past the quadrant.
      let lx = q.x, ly = q.y + 0.71
      parts.forEach(([l, v, c]) => {
        const label = `${fmt(v)} ${l}`, w = 0.3 + label.length * (12 / 72 * 0.5)
        if (lx + w > q.x + qw) { lx = q.x; ly += 0.32 }
        s.addShape(pres.shapes.RECTANGLE, { x: lx, y: ly + 0.07, w: 0.13, h: 0.13, fill: { color: c }, line: { color: c, width: 0 }, objectName: `Legend ${l} swatch` })
        text(s, label, { x: lx + 0.2, y: ly, w: w - 0.15, h: 0.28, fontSize: 12, color: C.text1, objectName: `Legend ${l}` })
        lx += w + 0.2
      })
      if (a.open > 0) text(s, a.openSplit ? `${fmt(a.open)} more ${a.open === 1 ? 'was' : 'were'} open at collection. Of these, ${a.openSplit.phrase}.` : `${fmt(a.open)} more ${a.open === 1 ? 'is' : 'are'} referred to your team for action or confirmation under the agreed notification process, or still in progress.`, { x: q.x, y: ly + 0.42, w: qw, h: 0.65, fontSize: 12, color: C.accent6, objectName: 'Referral note' })
    } else text(s, 'The combined alert result is reconciled before dispositions are presented.', { x: q.x, y: q.y, w: qw, h: 0.6, fontSize: 13, color: C.accent6, objectName: 'Disposition pending' })
    // Detections by source.
    q = quad(3, m.detections ? `${fmt(m.detections.total)} detections, by source` : 'Detections by source')
    if (m.detections) {
      const top = m.detections.bySource.slice(0, 5)
      s.addChart(pres.charts.BAR, [{ name: 'Detections', labels: top.map(d => d.name), values: top.map(d => d.total) }], {
        x: q.x - 0.1, y: q.y - 0.1, w: qw + 0.1, h: q.h - 0.25, barDir: 'bar', chartColors: [HEX.accent2], barGapWidthPct: 40,
        showValue: true, dataLabelPosition: 'outEnd', dataLabelColor: HEX.dk2, dataLabelFontSize: 12, dataLabelFontBold: true, dataLabelFontFace: '+mn-lt', dataLabelFormatCode: '#,##0',
        catAxisOrientation: 'maxMin', catAxisLabelColor: HEX.dk1, catAxisLabelFontSize: 12, catAxisLabelFontFace: '+mn-lt', valAxisHidden: true,
        valGridLine: { style: 'none' }, catGridLine: { style: 'none' }, showLegend: false, objectName: 'Detections chart'
      })
      text(s, 'Detections are correlated into alerts. One alert can carry several detections.', { x: q.x, y: BOTTOM - 0.3, w: qw, h: 0.3, fontSize: 10, color: C.accent6, objectName: 'Detections caption' })
    } else text(s, 'Detection sources are confirmed in the review.', { x: q.x, y: q.y, w: qw, h: 0.4, fontSize: 13, color: C.accent6, objectName: 'Detections empty' })
    s.addNotes(notesOf([
      m.ticketed ? 'An alert is a Sentinel record that opened a ticket with the managed security service. Informational severity is excluded, and detections are the records correlated into those alerts.' : m.detections && m.detections.allSources ? `Detections from ${m.detections.allSources} are correlated into alerts.` : 'Detections are correlated into alerts.',
      m.xdrScope.sentence,
      m.trendCoverage ? `${m.trendCoverage.sentence} ${m.trendCoverage.caption} Evidence ${m.trendCoverage.source}` : '',
      m.alerts ? `Closed alerts: ${fmt(m.alerts.benign)} benign positive, ${fmt(m.alerts.falsePositives)} false positive, ${fmt(m.alerts.truePositives)} true positive, ${fmt(m.alerts.unclassified)} unclassified.` : '',
      m.alerts && m.alerts.open > 0 ? (m.alerts.openSplit ? `Of the alerts open at collection, ${m.alerts.openSplit.phrase}. Evidence ${m.alerts.openSplit.source}` : 'The remaining alerts are referred to your team for action or confirmation under the agreed notification process, or are still under investigation.') : '',
      'Response times run from alert creation to recorded close, for every high severity alert created in the period and closed by collection. Every median and 90th percentile is shown, and one under 20 minutes or over one hour is covered in the review.',
      m.response && m.response.split ? `Of the high severity alerts, ${fmt(m.response.split.automation.n)} were closed by automation rules.${m.response.split.analyst && m.response.split.analyst.median ? ` Analyst-handled: median ${m.response.split.analyst.median.value}${m.response.split.analyst.p90 ? `, 90th percentile ${m.response.split.analyst.p90.value}` : ''}.` : ''}` : '',
      m.response && m.response.target ? m.response.target.sentence : ''
    ]))

    // 4a. The 90-day trend: alerts by week, response timing by month and the most common alert types.
    if (cs.ops.weekly.length || cs.ops.timing.length) {
      s = content('Operations and posture', 'The 90-day trend', `Alerts by week, response timing by month and the alert types behind them, ${m.period.label}`)
      const lw = CW * 0.52, rx = X0 + lw + 0.4, rw = CW - lw - 0.4
      eyebrow(s, 'Alerts created each week', X0, TOP, lw, C.text2, 'Weekly alerts')
      if (cs.ops.weekly.length) {
        const sev = ['High', 'Medium', 'Low'], colors = { High: HEX.sevHigh, Medium: HEX.sevMedium, Low: HEX.sevLow }
        s.addChart(pres.charts.BAR, sev.map(k => ({ name: k, labels: cs.ops.weekly.map(w => w.label), values: cs.ops.weekly.map(w => w[k.toLowerCase()]) })), {
          x: X0 - 0.1, y: TOP + 0.35, w: lw + 0.1, h: BOTTOM - TOP - 0.95, barDir: 'col', barGrouping: 'stacked', barGapWidthPct: 45,
          chartColors: sev.map(k => colors[k]), catAxisLabelColor: HEX.dk1, catAxisLabelFontSize: 9, catAxisLabelFontFace: '+mn-lt', catAxisLabelRotate: 315, valAxisLabelColor: HEX.accent6, valAxisLabelFontSize: 10, valAxisLabelFontFace: '+mn-lt',
          valGridLine: { color: HEX.track, size: 0.5 }, catGridLine: { style: 'none' }, showLegend: true, legendPos: 'b', legendFontSize: 10, legendFontFace: '+mn-lt', legendColor: HEX.dk1, objectName: 'Weekly alerts chart'
        })
        caption(s, cs.ops.weeklyNote || 'Weeks run 7 days from the window start.', X0, BOTTOM - 0.5, lw, 'Weekly alerts caption')
      } else text(s, 'Weekly volume is confirmed in the review.', { x: X0, y: TOP + 0.45, w: lw, h: 0.4, fontSize: 13, color: C.accent6, objectName: 'Weekly alerts empty' })
      eyebrow(s, 'Response timing by month, high severity', rx, TOP, rw, C.text2, 'Monthly timing')
      let ty = TOP + 0.4
      if (cs.ops.timing.length) {
        const cellT = (t, f) => t.withheld ? 'Not reported' : t[f] === null || t[f] === undefined ? 'Not available' : duration(t[f])
        ty = deckTable(s, ['Month', 'Closed', 'Median to acknowledge', 'Median to close', '90% closed within'], cs.ops.timing.map(t => [t.label, fmt(t.high.n), cellT(t.high, 'ack'), cellT(t.high, 'median'), cellT(t.high, 'p90')]), { x: rx, y: ty, w: rw, colW: [rw * 0.2, rw * 0.13, rw * 0.25, rw * 0.2, rw * 0.22], name: 'Monthly timing table', size: 11, numeric: [1, 2, 3, 4] })
        ty = caption(s, 'A month with fewer than 5 closed alerts reports no timing. A median under 20 minutes or a 90th percentile over one hour is covered in the review.', rx, ty + 0.05, rw, 'Monthly timing caption')
      }
      if (cs.ops.types.length) {
        eyebrow(s, 'Most common alert types', rx, ty + 0.15, rw, C.text2, 'Alert types')
        const room = Math.max(1, Math.floor((BOTTOM - ty - 0.6 - HEAD_ROW) / 0.27))
        deckTable(s, ['Alert type', 'Period', cs.month.short], cs.ops.types.slice(0, Math.min(5, room)).map(t => [t.title.length > 60 ? `${t.title.slice(0, 57).trim()}...` : t.title, fmt(t.total), fmt(t.month)]), { x: rx, y: ty + 0.5, w: rw, colW: [rw * 0.64, rw * 0.16, rw * 0.2], name: 'Alert types table', size: 10, numeric: [1, 2] })
      }
      s.addNotes(notesOf([`Alerts created each week over ${periodWord}, by severity.`, cs.ops.weeklyNote || '', cs.ops.timing.filter(t => !t.high.withheld).map(t => `${t.label}: high severity median time to close ${duration(t.high.median)} on ${plural(t.high.n, 'closed alert', 'closed alerts')}.`), cs.ops.types.slice(0, 5).map(t => `${t.title}: ${fmt(t.total)} over the period, ${fmt(t.month)} in ${cs.month.label}.`), cs.ops.typesWithheld ? `${plural(cs.ops.typesWithheld, 'alert whose title names an account, address, host or ticket is', 'alerts whose titles name an account, address, host or ticket are')} counted without the title.` : '']))
    }

    // 4b. Confirmed threats: up to five examples, highest severity first, when the pack has any. A pack with true
    // positives but no screened example (every title withheld, or rows without titles or tactics) still gets the
    // slide without the table, so the outcome cards never disappear with the examples.
    const tp = m.alerts ? m.alerts.truePositives : null
    if (m.threats || tp > 0) {
      s = content('Operations and posture', 'Confirmed threats', st.takeaways.threats)
      const HEAD_H = 0.4, GAP = 0.2, PAD_X = 0.1
      // The caption takes the lines it needs, so the table, the cards and the strip stay below it.
      const caption = m.threats
        ? `${m.threats.more ? `And ${plural(m.threats.moreAlerts, 'more confirmed alert', 'more confirmed alerts')} in ${plural(m.threats.more, 'further group', 'further groups')}. ` : ''}Classified as true positives by the SOC, grouped by alert title.`
        : `${fmt(tp)} ${tp === 1 ? 'alert' : 'alerts'} the SOC classified as ${tp === 1 ? 'a true positive' : 'true positives'} ${st.periodPhrase}.`
      const CAPTION_H = 0.17 + lines(caption, CW - 0.2, 11) * 0.18
      // The table, when there are examples. tableH is the room it takes above the caption.
      let tableH = 0
      if (m.threats) {
        const colW = [CW * 0.38, CW * 0.09, CW * 0.11, CW * 0.2, CW * 0.22]
        const head = ['Threat', 'Alerts', 'Severity', 'Attack stage', 'When'].map((t, i) => ({ text: t, options: { fontSize: 12, color: HEX.accent6, align: i === 1 ? 'right' : 'left', border: border(0.75) } }))
        // Rows hold two lines and grow for a longer title or stage, so the caption stays below the table. When the
        // rows would push the caption past BOTTOM, the body drops to 12 pt. If that is still too tall, long titles are
        // cut at a word before 110 characters and end in three dots.
        const room = BOTTOM - TOP - HEAD_H - GAP - CAPTION_H
        const lineH = size => size / 14 * 0.235
        const rowLines = (r, size) => Math.max(2, ...r.map((v, i) => lines(v, colW[i] - 2 * PAD_X, size, i === 0)))
        const cut = (t, cap) => { if (t.length <= cap) return t
          const words = t.slice(0, cap + 1).replace(/\s+\S*$/, '').replace(/[\s,.:-]+$/, '')
          return `${words.length >= cap / 2 && words.length <= cap ? words : t.slice(0, cap).trimEnd()}...` }
        const layout = (size, cap = Infinity) => {
          const cells = m.threats.examples.map(t => [cut(t.title, cap), fmt(t.alerts), t.severity, t.stage, glue(t.when)])
          const rowH = cells.map(r => rowLines(r, size) * lineH(size) + 0.15)
          return { size, cells, rowH, height: rowH.reduce((n, h) => n + h, 0) }
        }
        // The 80 character tier is a safety net: two-line titles always fit.
        const fit = [layout(14), layout(12), layout(12, 110)].find(l => l.height <= room) || layout(12, 80)
        const body = fit.cells.map(r => r.map((v, i) => ({ text: v, options: { fontSize: fit.size, color: i ? HEX.dk1 : HEX.dk2, bold: i === 0, align: i === 1 ? 'right' : 'left', valign: 'middle', border: border(0.5) } })))
        s.addTable([head, ...body], { x: X0, y: TOP, w: CW, colW, rowH: [HEAD_H, ...fit.rowH], margin: [0.05, PAD_X, 0.05, PAD_X], objectName: 'Confirmed threats table' })
        tableH = HEAD_H + fit.height + GAP
      }
      text(s, caption, { x: X0, y: TOP + tableH, w: CW, h: CAPTION_H, fontSize: 11, color: C.accent6, objectName: 'Confirmed threats caption' })
      // A short table leaves the slide empty, so the room below it carries what the confirmed threats add up to
      // (the outcome cards) and how every confirmed threat is handled (the strip). Five long titles leave no
      // room, and the slide then holds the table alone (Oct 14, 2026).
      // The strip and its note name only what the evidence records for each confirmed threat: detected, triaged
      // and classified. The CyberSOC report carries no data exfiltration or compromise determination (Oct 19, 2026).
      // The outcome cards stay within the evidence: the true positive count (OUT.1) and the rows (OUT.4) are
      // classifications regardless of status, so the cards never claim closure. The severity count comes from the
      // model, counted per alert before grouping.
      const high = m.threats ? m.threats.severities.High : 0
      const outcomeCards = [
        tp !== null && tp > 0 ? [fmt(tp), tp === 1 ? 'Confirmed threat' : 'Confirmed threats', `${tp === 1 ? 'An alert' : 'Alerts'} the SOC classified as ${tp === 1 ? 'a true positive' : 'true positives'} ${st.periodPhrase}.`] : null,
        m.threats && m.threats.alerts > 0 ? [fmt(high), high === 1 ? 'High severity alert' : 'High severity alerts', `Of the ${plural(m.threats.alerts, 'confirmed alert', 'confirmed alerts')} grouped above, at the severity Sentinel recorded.`] : null,
        st.speed ? [st.speed.value, sentence(st.speed.label), st.speed.sub] : null
      ].filter(Boolean).slice(0, 4)
      const handling = [['1 Detect', ' Sentinel and Defender detections are correlated into one alert'], ['2 Triage', ' the SOC triages each alert and confirms its severity'], ['3 Classify', ' the SOC records a true-positive classification on the alert']]
      const STRIP_H = 0.85, cardTop = TOP + tableH + CAPTION_H + 0.2
      const roomWithStrip = BOTTOM - STRIP_H - 0.25 - cardTop, roomAlone = BOTTOM - cardTop
      const cardH = outcomeCards.length && roomWithStrip >= 1.1 ? Math.min(1.6, roomWithStrip) : outcomeCards.length && roomAlone >= 1.1 ? Math.min(1.6, roomAlone) : 0
      if (cardH) {
        const ocw = (CW - (outcomeCards.length - 1) * 0.3) / outcomeCards.length
        outcomeCards.forEach(([value, label, sub], i) => {
          const x = X0 + i * (ocw + 0.3)
          card(s, x, cardTop, ocw, cardH, `Threat outcome ${i + 1} card`)
          rule(s, x, cardTop, ocw, C.accent1, 2.5, `Threat outcome ${i + 1} rule`)
          text(s, [{ text: value, options: { fontSize: 26, bold: true, color: C.accent2, breakLine: true } }, { text: label, options: { fontSize: 13, bold: true, color: C.text2, breakLine: true, paraSpaceBefore: 2 } }, { text: sub, options: { fontSize: 11, color: C.accent6, paraSpaceBefore: 4 } }], { x: x + 0.25, y: cardTop + 0.2, w: ocw - 0.5, h: cardH - 0.3, objectName: `Threat outcome ${i + 1}` })
        })
      }
      const strip = (cardH && roomWithStrip >= 1.1) || (!cardH && roomAlone >= STRIP_H + 0.1)
      if (strip) {
        card(s, X0, BOTTOM - STRIP_H, CW, STRIP_H, 'Threat handling card')
        text(s, 'EVERY CONFIRMED THREAT', { x: X0 + 0.25, y: BOTTOM - STRIP_H, w: 1.9, h: STRIP_H, fontSize: 10, bold: true, color: C.text2, charSpacing: 1.5, valign: 'middle', objectName: 'Threat handling label' })
        const hw = (CW - 2.4) / handling.length
        handling.forEach(([lead, rest], i) => text(s, [{ text: lead, options: { bold: true, color: C.accent2 } }, { text: rest, options: { color: C.text1 } }], { x: X0 + 2.3 + i * hw, y: BOTTOM - STRIP_H, w: hw - 0.15, h: STRIP_H, fontSize: 11, valign: 'middle', objectName: `Threat handling ${i + 1}` }))
      }
      s.addNotes(notesOf([
        m.threats ? 'These are alerts the SOC confirmed as true positive threats, grouped by alert title, highest severity first.' : '',
        m.ticketed ? 'Each one opened a ticket with the managed security service.' : '',
        st.takeaways.threats,
        cardH ? outcomeCards.map(([value, label, sub]) => `${value} ${label.charAt(0).toLowerCase() + label.slice(1)}. ${sub}`) : '',
        strip ? 'Every confirmed threat follows the same path: detections are correlated into one alert, the SOC triages it and confirms its severity, and the SOC records a true-positive classification.' : ''
      ]))
    }

    cyberSocSlides('Operations and posture')

    // 5. Control posture: pillar matrix and the foundational gaps panel. The headline measure column sits on a
    // light band with its figures in bold, one measure per line, so the lead reading of each pillar stands out.
    s = content('Operations and posture', 'Control posture', st.takeaways.posture)
    const mw = 7.85, cols = [1.85, 1.3, 1.3, mw - 4.45]
    const cx = [X0, X0 + cols[0], X0 + cols[0] + cols[1], X0 + cols[0] + cols[1] + cols[2]]
    const rh = 0.74
    card(s, cx[3] - 0.15, TOP, cols[3] + 0.15, 0.6 + st.matrix.length * rh - 0.05, 'Headline measure band')
    ;['Pillar', 'Foundational', 'Defense in depth', 'Headline measure'].forEach((h, i) => text(s, h, { x: cx[i], y: TOP, w: cols[i] - 0.15, h: 0.45, fontSize: 12, bold: true, color: i === 3 ? C.text2 : C.accent6, valign: 'bottom', objectName: `Matrix header ${i + 1}` }))
    rule(s, X0, TOP + 0.52, mw, C.text2, 1, 'Matrix header rule')
    // "180 of 194 users on MFA at sign-in · 3 users already on phishing-resistant sign-in" becomes two lines, each
    // led by its figure in bold.
    const measureRuns = measure => measure.split(' · ').flatMap((part, i, all) => {
      const hit = part.match(/^(\d[\d,.]*%?(?: of \d[\d,.]*)?)\s+(.*)$/)
      const runs = hit ? [{ text: hit[1], options: { fontSize: 11.5, bold: true, color: C.text2 } }, { text: ` ${hit[2]}`, options: { fontSize: 10.5, color: C.text1 } }] : [{ text: part, options: { fontSize: 10.5, color: C.text1 } }]
      if (i < all.length - 1) runs[runs.length - 1] = { ...runs[runs.length - 1], options: { ...runs[runs.length - 1].options, breakLine: true } }
      return runs
    })
    st.matrix.forEach((r, i) => {
      const y = TOP + 0.6 + i * rh
      text(s, r.group, { x: cx[0], y, w: cols[0] - 0.15, h: rh - 0.08, fontSize: 15, bold: true, color: C.text2, valign: 'middle', objectName: `${r.group} name` })
      ;[[r.foundational, 1, r.foundational.measured && r.foundational.enforced === r.foundational.measured ? C.accent3 : C.accent4], [r.defense, 2, C.accent2]].forEach(([t, col, fill]) => {
        const tier = col === 1 ? 'foundational' : 'defense'
        // A count holding a control on a small sample names it on a second line, above the meter (issue #24). The box
        // takes the column to 0.12 in short of the next, still clear of the headline band, so the line never wraps.
        const count = t.measured ? `${t.enforced} of ${t.measured}` : 'Not measured'
        if (t.small) text(s, [{ text: count, options: { fontSize: 15, bold: true, color: C.text2, breakLine: true } }, { text: smallSampleText(t.small), options: { fontSize: 9, color: C.accent6 } }], { x: cx[col], y: y + 0.03, w: cols[col] - 0.12, h: 0.42, objectName: `${r.group} ${tier} count` })
        else text(s, count, { x: cx[col], y: y + 0.1, w: cols[col] - 0.2, h: 0.32, fontSize: t.measured ? 15 : 12, bold: !!t.measured, color: t.measured ? C.text2 : C.accent6, objectName: `${r.group} ${tier} count` })
        if (t.measured) meter(s, cx[col], y + 0.47, cols[col] - 0.25, t.pct, fill, `${r.group} ${tier}`)
      })
      text(s, r.measure ? measureRuns(r.measure) : 'Readings completed in the review', { x: cx[3], y, w: cols[3] - 0.15, h: rh - 0.08, fontSize: 10.5, color: C.accent6, valign: 'middle', objectName: `${r.group} measure` })
      if (i < st.matrix.length - 1) rule(s, X0, y + rh - 0.02, mw, HEX.track, 0.75, `${r.group} rule`)
    })
    const ay = TOP + 0.6 + st.matrix.length * rh + 0.05
    card(s, X0, ay, mw, BOTTOM - ay, 'All pillars card')
    text(s, 'All pillars', { x: cx[0] + 0.15, y: ay, w: cols[0], h: BOTTOM - ay, fontSize: 15, bold: true, color: C.text2, valign: 'middle', objectName: 'All pillars name' })
    // Bold rides on the figure run, so the small sample line under it reads as a note.
    const allCount = t => [{ text: t.measured ? `${t.enforced} of ${t.measured}` : '–', options: { fontSize: 20, bold: true, color: C.accent2, breakLine: !!t.small } }, ...(t.small ? [{ text: smallSampleText(t.small), options: { fontSize: 9, color: C.accent6 } }] : [])]
    text(s, allCount(st.foundational), { x: cx[1], y: ay, w: cols[1], h: BOTTOM - ay, fontSize: 20, color: C.accent2, valign: 'middle', objectName: 'All pillars foundational' })
    text(s, allCount(st.defense), { x: cx[2], y: ay, w: cols[2], h: BOTTOM - ay, fontSize: 20, color: C.accent2, valign: 'middle', objectName: 'All pillars defense' })
    text(s, 'Foundational and defense in depth controls enforced, of those measured', { x: cx[3], y: ay, w: cols[3] - 0.1, h: BOTTOM - ay, fontSize: 11, color: C.accent6, valign: 'middle', objectName: 'All pillars note' })
    // Drift panel.
    const px = X0 + mw + 0.4, pw = CW - mw - 0.4
    card(s, px, TOP, pw, BOTTOM - TOP, 'Drift panel')
    // The note under the title ends above the first item's rule (TOP + 1.02), which leaves room for two 12 pt lines.
    // A reviewed drift reference too long for that is cut with three dots, and the speaker notes carry the full line.
    const headW = pw - 0.6, headRoom = (1.1 - 0.08 - 0.25) - 18 / 72 * 1.2 - 4 / 72
    let driftNote = st.driftNote
    if (st.drift.length && st.driftAction && lines(glue(driftNote), headW, 12) * 12 / 72 * 1.2 > headRoom) {
      const ref = st.driftAction.reference, note = r => `Below the baseline at collection. Fixes ${st.driftAction.label.toLowerCase()} (${r}).`
      let n = ref.length
      while (n > 8 && lines(glue(note(`${ref.slice(0, n)}...`)), headW, 12) * 12 / 72 * 1.2 > headRoom) n--
      driftNote = note(`${ref.slice(0, n)}...`)
    }
    text(s, [{ text: 'Foundational gaps', options: { fontSize: 18, bold: true, color: C.text2, breakLine: true } }, { text: st.drift.length ? driftNote : 'No foundational gaps. Every measured foundational control reads E.', options: { fontSize: 12, color: C.accent6, paraSpaceBefore: 4 } }], { x: px + 0.3, y: TOP + 0.25, w: pw - 0.6, h: 1.0, objectName: 'Drift heading' })
    let dy = TOP + 1.1
    // Each item takes the lines its label and figure line need. Items stop above the legend and the tail line
    // (the gaps left in the register), so nothing overlaps.
    const itemW = pw - 1.1, tailTop = BOTTOM - 0.6 - 0.62
    const shown = []
    for (const c of st.drift) {
      // The figure line carries the ratio behind a Mostly enforced policy and what a control is missing, such as
      // the resource types outside workload protection, ahead of the pillar name.
      const figure = `${c.valueText}${c.detail ? `, ${c.detail}` : ''} · ${c.group}`
      const h = (Math.min(3, lines(c.label, itemW, 13, true)) + lines(figure, itemW, 12)) * 0.21 + 0.08
      if (dy + h > tailTop) break
      const i = shown.length
      rule(s, px + 0.3, dy - 0.08, pw - 0.6, HEX.track, 0.75, `Drift ${i + 1} rule`)
      markChip(s, c.mark, px + 0.3, dy + 0.04, 0.36, 0.3, 12, `Drift ${i + 1} mark`)
      text(s, [{ text: c.label, options: { fontSize: 13, bold: true, color: C.text2, breakLine: true } }, { text: figure, options: { fontSize: 12, color: C.accent6, paraSpaceBefore: 2 } }], { x: px + 0.8, y: dy, w: itemW, h, objectName: `Drift ${i + 1}` })
      shown.push(c)
      dy += h + 0.1
    }
    const tail = st.drift.length > shown.length ? `${plural(st.drift.length - shown.length, 'more foundational gap is', 'more foundational gaps are')} in the register.` : ''
    if (tail) text(s, tail, { x: px + 0.3, y: tailTop, w: pw - 0.6, h: 0.6, fontSize: 11, color: C.accent6, valign: 'bottom', objectName: 'Drift tail' })
    text(s, 'E enforced, 90% or more · P partial, 50 to 89%, or a scoped policy whatever its ratio · N not yet enforced, below 50%', { x: px + 0.3, y: BOTTOM - 0.55, w: pw - 0.6, h: 0.42, fontSize: 11, color: C.accent6, objectName: 'Mark legend' })
    s.addNotes(notesOf([
      'Foundational controls are the baseline the service holds every environment to, and each is expected to read enforced at every review. One that reads below E is a gap against that baseline. Atmosera owns the fix and sets a fix date at this review, and it is first on the roadmap. Defense in depth controls are layered on top, and each waits on something your team approves, schedules or licenses. Every reading describes the state at collection, not a change since the last review.',
      'E means 90 percent or more of in-scope resources, P 50 to 89 percent and N below 50 percent. A policy that stops short of every user on every application in every condition reads P however high the sign-in ratio behind it.',
      st.ungathered.length ? `${plural(st.ungathered.length, 'control', 'controls')} could not be graded from the collected evidence and ${st.ungathered.length === 1 ? 'is' : 'are'} listed in the appendix.` : '',
      st.drift.length && st.driftAction ? `Foundational fixes: ${st.driftAction.label.toLowerCase()}, from the reviewed action record ${st.driftAction.reference}, reviewed ${st.driftAction.reviewed}.` : '',
      m.pillars.map(p => `${p.name}. ${p.headline}. ${p.narrative}`)
    ]))

    // 5b. Measured outcomes by pillar: the headline each pillar earned, the narrative behind it, the lead
    // measure and the callout, as the HTML pillar page shows them. A narrative that would not fit its row is
    // cut at a sentence end, and the full text goes to the speaker notes. The sentences a pillar keeps (the
    // endpoint coverage and the EW.1-GAPS reconciliation when machines are not reporting) are never cut: the
    // other sentences go first, then the row takes the pillar's short headline, then it gives the measure column
    // to the story, since the kept coverage sentence carries the measure's figure, then it sets the story in 9 pt.
    // When even that cannot hold them (EW.1-GAPS can name 16 reason and product groups), the row keeps its standard
    // layout with the kept sentences that fit and a pointer, and the next slide carries the full reading, so
    // nothing kept leaves the deck and no row runs into the next (Oct 15, 2026).
    if (m.pillars.length) {
      s = content('Operations and posture', 'Measured outcomes by pillar', st.takeaways.pillars)
      const prow = (BOTTOM - TOP) / m.pillars.length, nameW = 1.9, storyX = X0 + nameW + 0.2, storyW = 6.3, measX = storyX + storyW + 0.3, measW = CW - nameW - 0.2 - storyW - 0.3
      const sentences = t => clean(t).split(/(?<=\.)\s+(?=[A-Z0-9])/).filter(Boolean)
      const POINTER = 'The full reading continues on the next slide.'
      const continued = []
      m.pillars.forEach((p, i) => {
        const y = TOP + i * prow
        if (i) rule(s, X0, y - 0.04, CW, HEX.track, 0.75, `${p.name} outcome rule`)
        const reg = st.matrix.find(r => r.group === p.name)
        text(s, [{ text: p.name, options: { fontSize: 14, bold: true, color: C.text2, breakLine: true } }, { text: reg && reg.foundational.measured ? `${reg.foundational.enforced} of ${reg.foundational.measured} foundational enforced${reg.foundational.small ? `, ${smallSampleText(reg.foundational.small)}` : ''}` : 'Readings completed in the review', options: { fontSize: 10, color: C.accent6, paraSpaceBefore: 3 } }], { x: X0, y: y + 0.06, w: nameW, h: prow - 0.12, objectName: `${p.name} outcome name` })
        const room = prow - 0.14, keep = new Set(sentences(p.keep)), wideW = CW - nameW - 0.2
        const needs = (head, w, size, body) => lines(head, w, 11, true) * 0.18 + lines(body, w, size) * size * 0.0165 + 0.05
        // Drops the last sentence that is neither the first nor kept until the row fits or nothing else can go.
        const fit = (head, w, size) => {
          let parts = sentences(p.narrative)
          while (parts.length > 1 && needs(head, w, size, parts.join(' ')) > room) {
            const cut = parts.findLastIndex((t, k) => k > 0 && !keep.has(t))
            if (cut < 0) break
            parts = parts.filter((_, k) => k !== cut)
          }
          return parts.join(' ')
        }
        // The first layout that fits, the last one otherwise. Only a row with kept sentences has fallbacks.
        const layouts = [[p.headline, storyW, 10], ...(keep.size ? [[p.headlineShort, storyW, 10], [p.headline, wideW, 10], [p.headlineShort, wideW, 10], [p.headlineShort || p.headline, wideW, 9]] : [])]
          .filter(([head]) => head).map(([head, w, size]) => { const body = fit(head, w, size); return { head, w, size, body, fits: needs(head, w, size, body) <= room } })
        let { head, w, size, body } = layouts.find(l => l.fits) || layouts[layouts.length - 1]
        if (keep.size && !layouts.some(l => l.fits)) {
          // The kept sentences in narrative order, up to the first that would not fit beside the pointer. The first
          // sentence always stays, as in every other row.
          head = p.headlineShort || p.headline; w = storyW; size = 10
          const kept = sentences(p.narrative).filter((t, k) => k === 0 || keep.has(t)), shown = kept.slice(0, 1)
          for (const t of kept.slice(1)) { if (needs(head, w, size, [...shown, t, POINTER].join(' ')) > room) break; shown.push(t) }
          body = [...shown, POINTER].join(' ')
          continued.push(p)
        }
        text(s, [{ text: head, options: { fontSize: 11, bold: true, color: C.text2, breakLine: true } }, { text: body, options: { fontSize: size, color: C.text1, paraSpaceBefore: 3 } }], { x: storyX, y: y + 0.06, w, h: prow - 0.12, objectName: `${p.name} outcome story` })
        if (w > storyW) return
        if (p.measure) {
          text(s, p.measure.label, { x: measX, y: y + 0.06, w: measW, h: 0.22, fontSize: 10, color: C.accent6, objectName: `${p.name} measure label` })
          meter(s, measX, y + 0.36, measW - 1.15, p.measure.pct, p.measure.mark === 'E' ? C.accent3 : p.measure.mark === 'N' ? C.accent4 : C.accent2, `${p.name} outcome`)
          text(s, `${fmt(p.measure.good)} of ${fmt(p.measure.total)}`, { x: measX + measW - 1.1, y: y + 0.26, w: 1.1, h: 0.32, fontSize: 13, bold: true, color: C.text2, align: 'right', valign: 'middle', objectName: `${p.name} measure value` })
        }
        if (p.callout) text(s, [{ text: p.callout.value, options: { fontSize: 14, bold: true, color: C.accent2 } }, { text: `  ${p.callout.label}`, options: { fontSize: 10, color: C.accent6 } }], { x: measX, y: y + (p.measure ? 0.64 : 0.08), w: measW, h: 0.4, valign: 'middle', objectName: `${p.name} callout` })
      })
      s.addNotes(notesOf(['Each pillar leads with the statement its strongest measure earned. The pillars that read lower need change inside the environment, and each of those items is sequenced on the roadmap.', m.pillars.map(p => `${p.name}. ${p.headline}. ${p.narrative} Evidence ${p.source}`)]))
      // 5c. The continuation: each pillar the slide could not hold in full, with its headline and whole narrative.
      if (continued.length) {
        s = content('Operations and posture', 'Measured outcomes by pillar, continued', `${list(continued.map(p => p.name))}: the full reading behind the figure`)
        let cy = TOP
        for (const p of continued) {
          // The story takes the lines its text needs, with the source line under it, all inside the card.
          const cw = CW - 0.8, storyH = lines(p.name, cw, 15, true) * 0.25 + lines(p.headline, cw, 13, true) * 0.22 + lines(p.narrative, cw, 12) * 0.2 + 0.15
          const h = Math.min(BOTTOM - cy, storyH + 0.75)
          card(s, X0, cy, CW, h, `${p.name} continued card`)
          text(s, [{ text: p.name, options: { fontSize: 15, bold: true, color: C.text2, breakLine: true } }, { text: p.headline, options: { fontSize: 13, bold: true, color: C.text2, breakLine: true, paraSpaceBefore: 4 } }, { text: p.narrative, options: { fontSize: 12, color: C.text1, paraSpaceBefore: 6 } }], { x: X0 + 0.4, y: cy + 0.2, w: cw, h: h - 0.75, objectName: `${p.name} continued story` })
          text(s, `Evidence ${p.source}`, { x: X0 + 0.4, y: cy + h - 0.45, w: cw, h: 0.25, fontSize: 9, color: C.accent6, objectName: `${p.name} continued source` })
          cy += h + 0.2
        }
        s.addNotes(notesOf(['The previous slide could not hold the full reading for this pillar, so it is set out here in full.', continued.map(p => `${p.name}. ${p.headline}. ${p.narrative}`)]))
      }
    }
  }

  if (!balanced) {
    pres.addSection({ title: 'Threats and vulnerabilities' })
    cyberSocSlides('Threats and vulnerabilities')
  }

  // 6. Hardening roadmap: Now, Next and Later.
  pres.addSection({ title: 'Roadmap and decisions' })
  s = content('Roadmap and decisions', 'Hardening roadmap', st.takeaways.roadmap)
  const hw = (CW - 0.8) / 3, ruleColor = { now: C.text2, next: C.accent2, later: HEX.sevLow }, stripY = BOTTOM - 0.7
  st.roadmap.forEach((h, i) => {
    const x = X0 + i * (hw + 0.4)
    text(s, h.label, { x, y: TOP - 0.05, w: hw * 0.4, h: 0.42, fontSize: 20, bold: true, color: C.text2, valign: 'bottom', objectName: `${h.label} heading` })
    text(s, h.when, { x: x + hw * 0.35, y: TOP - 0.05, w: hw * 0.65, h: 0.42, fontSize: 12, color: C.accent6, align: 'right', valign: 'bottom', objectName: `${h.label} when` })
    rule(s, x, TOP + 0.45, hw, ruleColor[h.key], 2.5, `${h.label} rule`)
    // One flowing text box per column, so spacing comes from the paragraphs, not from estimates.
    // Items that would run into the strip are named in an "Also" line instead.
    const room = stripY - 0.1 - (TOP + 0.6)
    let used = 0
    const fit = [], rest = []
    h.items.forEach(it => {
      const need = lines(it.title, hw, 14, true) * 0.235 + lines(it.evidence, hw, 12) * 0.2 + 0.14
      if (used + need > room + 0.15 || rest.length) rest.push(it.title); else { fit.push(it); used += need }
    })
    if (rest.length && used + 0.3 > room + 0.15 && fit.length) rest.unshift(fit.pop().title)
    const runs = fit.flatMap((it, n) => [
      { text: it.title, options: { fontSize: 14, bold: true, color: C.text2, breakLine: true, paraSpaceBefore: n ? 9 : 0 } },
      { text: it.evidence, options: { fontSize: 12, color: C.text1, breakLine: n < fit.length - 1 || rest.length > 0, paraSpaceBefore: 2 } }
    ])
    if (rest.length) runs.push({ text: `Also: ${rest.join(', ')}.`, options: { fontSize: 11, color: C.accent6, paraSpaceBefore: 9 } })
    if (!h.items.length) runs.push({ text: h.key === 'now' ? 'Nothing needs action in the next 30 days.' : 'Nothing in this horizon.', options: { fontSize: 12, color: C.accent6 } })
    text(s, runs, { x, y: TOP + 0.6, w: hw, h: stripY - 0.1 - (TOP + 0.6), objectName: `${h.label} items` })
  })
  card(s, X0, stripY, CW, 0.7, 'Every change card')
  text(s, 'EVERY CHANGE', { x: X0 + 0.25, y: stripY, w: 1.5, h: 0.7, fontSize: 11, bold: true, color: C.text2, charSpacing: 1.5, valign: 'middle', objectName: 'Every change label' })
  ;[['1 Confirm', ' scope and business impact'], ['2 Pilot', ' in report-only mode with your team'], ['3 Verify', ' by recollecting the evidence']].forEach(([lead, rest], i) => {
    const sw = (CW - 2.1) / 3
    text(s, [{ text: lead, options: { bold: true, color: C.accent2 } }, { text: rest, options: { color: C.text1 } }], { x: X0 + 2.05 + i * sw, y: stripY, w: sw - 0.1, h: 0.7, fontSize: 12, valign: 'middle', objectName: `Step ${i + 1}` })
  })
  s.addNotes(notesOf([`Priorities reflect the evidence collected ${m.readDate}. Horizons are proposed for agreement today. Atmosera recommends staging each enforcement in an audit or report-only mode where the control supports one, reviewing it with your team, then turning it on.`,
    st.drift.length ? 'Closing the foundational gaps is Atmosera\'s work, with a fix date set at this review.' : '',
    m.priorities.map(p => `${p.title}. ${p.action} Outcome: ${p.success}`), st.headroom]))

  // 6b. Priority workstreams: the first three priorities with their evidence, the action and the outcome, as
  // the HTML roadmap page shows them, then the rest in one line.
  if (balanced && m.priorities.length) {
    s = content('Roadmap and decisions', 'Priority workstreams', st.takeaways.priorities)
    const top = m.priorities.slice(0, 3), rest = m.priorities.slice(3), pcw = (CW - 0.6) / 3, alsoH = rest.length ? 0.7 : 0, pch = BOTTOM - TOP - (rest.length ? alsoH + 0.25 : 0)
    top.forEach((p, i) => {
      const x = X0 + i * (pcw + 0.3)
      card(s, x, TOP, pcw, pch, `Priority ${i + 1} card`)
      rule(s, x, TOP, pcw, i ? C.accent2 : C.text2, 2.5, `Priority ${i + 1} rule`)
      // 11 pt unless the three blocks would run past the card, then 10 pt.
      const bodyW = pcw - 0.6
      const need = size => 0.75 + [p.evidence, p.action, p.success].reduce((n, t) => n + 0.3 + lines(t, bodyW, size) * (size / 72 * 1.2), 0)
      const size = need(11) <= pch - 0.4 ? 11 : 10
      const block = (head, body) => [{ text: head.toUpperCase(), options: { fontSize: 9, bold: true, color: C.accent2, charSpacing: 1.2, breakLine: true, paraSpaceBefore: 8 } }, { text: body, options: { fontSize: size, color: C.text1, breakLine: true, paraSpaceBefore: 2 } }]
      text(s, [
        { text: `${String(i + 1).padStart(2, '0')}   ${i === 0 ? 'FIRST WORKSTREAM' : 'SEQUENCED'}`, options: { fontSize: 10, bold: true, color: C.accent6, charSpacing: 1.2, breakLine: true } },
        { text: p.title, options: { fontSize: 16, bold: true, color: C.text2, breakLine: true, paraSpaceBefore: 4 } },
        ...block('Evidence', p.evidence), ...block('Action', p.action), ...block('Outcome', p.success)
      ], { x: x + 0.3, y: TOP + 0.2, w: bodyW, h: pch - 0.35, objectName: `Priority ${i + 1}` })
    })
    if (rest.length) {
      card(s, X0, BOTTOM - alsoH, CW, alsoH, 'Also sequenced card')
      text(s, [{ text: 'ALSO SEQUENCED   ', options: { fontSize: 10, bold: true, color: C.text2, charSpacing: 1.5 } }, { text: rest.map((p, i) => `${String(i + 4).padStart(2, '0')} ${p.title}`).join('   ·   '), options: { fontSize: 11, color: C.text1 } }], { x: X0 + 0.25, y: BOTTOM - alsoH, w: CW - 0.5, h: alsoH, valign: 'middle', objectName: 'Also sequenced' })
    }
    s.addNotes(notesOf([`Priorities reflect the evidence collected ${m.readDate}. Each one names the evidence, the action and the outcome we verify at the next review.`, m.priorities.map(p => `${p.title}. ${p.evidence} ${p.action} Outcome: ${p.success}`)]))
  }

  // 7. MFA method update: the users still signing in with text message or voice, and the plan to move each one
  // to a stronger method before Microsoft retires those methods. Never framed as passwordless (Oct 14, 2026).
  const methods = m.mfaMethods && m.mfaMethods.retiring > 0 ? m.mfaMethods : null
  if (methods) {
    s = content('Roadmap and decisions', 'MFA method update', st.takeaways.methods)
    const lw = 6.1
    if (st.deadlineDays !== null && st.deadlineDays > 0) {
      text(s, fmt(st.deadlineDays), { x: X0 - 0.05, y: TOP - 0.15, w: 2.6, h: 1.25, fontSize: 80, bold: true, color: C.accent2, valign: 'middle', objectName: 'Countdown' })
      text(s, [{ text: `days to move ${plural(methods.retiring, 'user', 'users')}`, options: { fontSize: 18, bold: true, color: C.text2, breakLine: true } }, { text: `From ${st.readShort} to ${st.deadlineShort}, when text message and voice sign-in retire for most users, and ${RETIREMENT.later.short} for ${RETIREMENT.later.who}`, options: { fontSize: 12, color: C.accent6, paraSpaceBefore: 2 } }], { x: X0 + 2.6, y: TOP + 0.1, w: lw - 2.6, h: 1.2, objectName: 'Countdown label' })
    } else text(s, [{ text: fmt(methods.retiring), options: { fontSize: 60, bold: true, color: C.accent2, breakLine: true } }, { text: 'users still sign in with text message or voice', options: { fontSize: 16, bold: true, color: C.text2 } }], { x: X0, y: TOP, w: lw, h: 1.3, objectName: 'Retiring users' })
    rule(s, X0, TOP + 1.4, lw, C.text2, 1, 'Methods rule')
    eyebrow(s, 'Users by sign-in method, last 30 days', X0, TOP + 1.55, lw, C.text2, 'Methods')
    const bars = [['Authenticator app or OTP token', methods.authenticator, C.accent2], ['Text message or voice', methods.retiring, C.accent4], ['Phishing-resistant', methods.resistant, C.accent3]]
    const maxM = Math.max(1, ...bars.map(([, v]) => v))
    bars.forEach(([l, v, c], i) => {
      const y = TOP + 2.05 + i * 0.5
      text(s, l, { x: X0, y, w: 2.9, h: 0.35, fontSize: 13, bold: i === 1, color: C.text1, valign: 'middle', objectName: `Method ${i + 1} label` })
      if (v > 0) s.addShape(pres.shapes.RECTANGLE, { x: X0 + 2.95, y: y + 0.07, w: Math.max(0.05, 2.35 * v / maxM), h: 0.22, fill: { color: c }, line: { color: c, width: 0 }, objectName: `Method ${i + 1} bar` })
      text(s, fmt(v), { x: X0 + lw - 0.75, y, w: 0.75, h: 0.35, fontSize: 14, bold: true, color: C.text2, align: 'right', valign: 'middle', objectName: `Method ${i + 1} value` })
    })
    text(s, methods.reliance, { x: X0, y: TOP + 3.65, w: lw, h: 0.5, fontSize: 12, color: C.accent6, objectName: 'Methods caption' })
    const steps = methods.steps
    const sx = X0 + lw + 0.5, sw = CW - lw - 0.5
    steps.forEach(([head, body], i) => {
      const y = TOP + i * 1.08
      chip(s, String(i + 1), sx, y + 0.05, 0.5, 0.5, C.text2, 16, `Step ${i + 1} number`)
      text(s, [{ text: head, options: { fontSize: 17, bold: true, color: C.text2, breakLine: true } }, { text: body, options: { fontSize: 13, color: C.text1, paraSpaceBefore: 2 } }], { x: sx + 0.7, y, w: sw - 0.7, h: 1.0, objectName: `Step ${i + 1}` })
    })
    card(s, X0, BOTTOM - 0.7, CW, 0.7, 'Outcome strip')
    text(s, [{ text: 'OUTCOME   ', options: { bold: true, color: C.text2, charSpacing: 1.5, fontSize: 11 } }, { text: methods.outcome, options: { color: C.text1, fontSize: 13 } }], { x: X0 + 0.25, y: BOTTOM - 0.7, w: CW - 0.5, h: 0.7, valign: 'middle', objectName: 'Outcome' })
    s.addNotes(notesOf([`${plural(methods.retiring, 'user', 'users')} signed in with text message or voice over the last 30 days. Sign-in use alone does not show that a user has no other method. ${methods.reliance}`, methods.timeline, methods.authenticator ? `${plural(methods.authenticator, 'user', 'users')} signed in with the Microsoft Authenticator app or an OTP token.` : '', `The plan notifies the affected users, registers each one on a passkey (in Microsoft Authenticator, a Microsoft Entra passkey on Windows or a FIDO2 security key) or on Windows Hello for Business in guided waves, removes text message and voice from the allowed methods under change control, and confirms readiness with a final sweep before ${methods.deadline}. Microsoft Authenticator push is outside this retirement and stays supported. A telephony provider from Microsoft Security Store is kept only for a documented regulatory or operational need.`]))
  }

  // 8. Decisions needed
  s = pres.addSlide({ masterName: 'Atmosera Decisions', sectionTitle: 'Roadmap and decisions' })
  s.addText('BEFORE THE NEXT REVIEW', { placeholder: 'eyebrow' })
  s.addText('Decisions needed', { placeholder: 'title' })
  s.addText(st.takeaways.decisions, { placeholder: 'subtitle' })
  if (st.asks.length) {
    const aw = (9.7 - 0.25) / 2, rows = Math.ceil(st.asks.length / 2), ah = Math.min(2.0, (6.6 - 2.45 - (rows - 1) * 0.25) / rows)
    st.asks.forEach((a, i) => {
      // An odd last card spans both columns, so the grid never shows an empty slot.
      const wide = i === st.asks.length - 1 && st.asks.length % 2 === 1 && st.asks.length > 1
      const x = 0.7 + (wide ? 0 : (i % 2) * (aw + 0.25)), y = 2.45 + Math.floor(i / 2) * (ah + 0.25), cw = wide ? 9.7 : aw, ch = wide ? Math.min(ah, 1.4) : ah
      s.addShape(pres.shapes.RECTANGLE, { x, y, w: cw, h: ch, fill: { color: HEX.dk2, transparency: 12 }, line: { color: HEX.accent5, width: 0.75 }, objectName: `Ask ${i + 1} card` })
      // A reviewed status line sits under the body. The body steps down from 13 pt to 10 pt until the card holds it.
      // If it still does not fit, the owner is cut first, then the reference, each with three dots, so the status, the
      // target date and the review date stay. The speaker notes keep the full attribution.
      const tw = cw - 0.6, th = ch - 0.3, x0 = a.action
      const tall = (size, status) => (14 + 4) / 72 * 1.2 + lines(glue(a.title), tw, 18, true) * 18 / 72 * 1.2 + 4 / 72 + lines(glue(a.bodyText), tw, size) * size / 72 * 1.2 + (status ? 4 / 72 + lines(glue(status), tw, size - 1) * (size - 1) / 72 * 1.2 : 0)
      const dots = (t, n) => n >= t.length ? t : `${t.slice(0, n).replace(/[\s,.]+$/, '')}...`
      const statusOf = (owner, ref) => x0 ? `${x0.label}${owner ? `, owner ${owner}` : ''}${x0.targetDate ? `, target ${x0.targetDate}` : ''} (${ref}, reviewed ${x0.reviewed}).` : ''
      let status = x0 ? statusOf(x0.owner, x0.reference) : ''
      const size = [13, 12, 11, 10].find(n => tall(n, status) <= th) || 10
      if (x0 && tall(size, status) > th) {
        let o = x0.owner.length, r = x0.reference.length
        while (o > 0 && tall(size, statusOf(dots(x0.owner, o), x0.reference)) > th) o--
        while (r > 8 && tall(size, statusOf(o ? dots(x0.owner, o) : '', dots(x0.reference, r))) > th) r--
        status = statusOf(o ? dots(x0.owner, o) : '', dots(x0.reference, r))
      }
      text(s, [{ text: String(i + 1).padStart(2, '0'), options: { fontSize: 14, bold: true, color: C.accent1, breakLine: true } }, { text: a.title, options: { fontSize: 18, bold: true, color: C.background1, breakLine: true, paraSpaceBefore: 4 } }, { text: a.bodyText, options: { fontSize: size, color: C.background2, paraSpaceBefore: 4, breakLine: !!status } }, ...(status ? [{ text: status, options: { fontSize: size - 1, color: C.background2, paraSpaceBefore: 4 } }] : [])], { x: x + 0.3, y: y + 0.2, w: tw, h: th, objectName: `Ask ${i + 1}` })
    })
  } else {
    s.addShape(pres.shapes.RECTANGLE, { x: 0.7, y: 2.55, w: 9.7, h: 1.3, fill: { color: HEX.dk2, transparency: 12 }, line: { color: HEX.accent5, width: 0.75 }, objectName: 'No asks card' })
    text(s, 'Nothing needs approval or access from your team before the next review. The roadmap proceeds as sequenced.', { x: 1.0, y: 2.55, w: 9.1, h: 1.3, fontSize: 16, color: C.background1, valign: 'middle', objectName: 'No asks' })
  }
  text(s, 'At the next review we recollect the evidence and verify each outcome.', { x: 0.7, y: 6.82, w: 9.7, h: 0.35, fontSize: 13, color: C.background2, objectName: 'Next review' })
  s.addNotes(notesOf(['Close on the decisions. Each one unblocks a roadmap item, or lets us grade a control we cannot see today.', st.asks.map(a => `${a.title}. ${a.body}`), st.settledAsks.length ? `No longer asked, from reviewed action records: ${st.settledAsks.map(a => `${a.title}, ${a.status}`).join('. ')}.` : '']))

  // Appendix: the control register, two pillars per slide, and on A3 how we grade.
  if (balanced) {
    pres.addSection({ title: 'Appendix' })
    const legend = 'E enforced, 90% or more · P partial, 50 to 89%, or a scoped policy whatever its ratio · N not yet enforced · – not gathered'
    const VALUE_W = 1.55
    // The exception count of a control at E rides on its label line, so it adds a line only when it wraps there, and so
    // does the excluded sign-in account count of a device code or legacy authentication block in force (issue #27). The
    // small sample flag (issue #24) rides on the figure in the value column, "3 of 3 · small sample", so it never
    // lengthens the label. Where the two do not fit one line (Arial widths, bold figure), the flag goes under the figure
    // and the row takes two lines.
    const suffix = c => c.exceptionText ? ` · ${c.exceptionText}` : ''
    const SAMPLE_SEP = ' · '
    const sampleInline = (c, size) => c.valueText.length * size / 72 * 0.55 + (SAMPLE_SEP + c.sampleText).length * (size - 1) / 72 * 0.46 <= VALUE_W
    const lineH = size => ({ 12: 0.215, 11: 0.2 })[size] || 0.185
    const rowLines = (c, labelW, size) => Math.max(c.sampleText && !sampleInline(c, size) ? 2 : 1, Math.min(suffix(c) ? 3 : 2, lines(c.label + suffix(c), labelW, size)) + (c.detail ? lines(c.detail, labelW, size - 1) : 0))
    // The largest size at which every column fits, down to 10 pt.
    const registerSize = (regs, w) => {
      const labelW = w - 0.55 - VALUE_W
      const fits = size => regs.every(reg => {
        const tiers = [reg.foundational, reg.defense].filter(r => r.length)
        const need = tiers.reduce((n, rows) => n + rows.reduce((k, c) => k + rowLines(c, labelW, size) * lineH(size) + 0.08, 0), 0)
        return need <= 7.2 - TOP - 0.45 - tiers.length * 0.52
      })
      return fits(12) ? 12 : fits(11) ? 11 : 10
    }
    const pillarColumn = (sl, reg, x, w, size) => {
      text(sl, reg.group, { x, y: TOP - 0.05, w: w * 0.62, h: 0.4, fontSize: 18, bold: true, color: C.text2, objectName: `${reg.group} register heading` })
      text(sl, reg.summary, { x: x + w * 0.5, y: TOP - 0.05, w: w * 0.5, h: 0.4, fontSize: 11, color: C.accent6, align: 'right', valign: 'middle', objectName: `${reg.group} register summary` })
      const tiers = [['foundational', 'Foundational', reg.foundational], ['defense', 'Defense in depth', reg.defense]].filter(([, , rows]) => rows.length)
      const labelW = w - 0.55 - VALUE_W
      let y = TOP + 0.45
      tiers.forEach(([key, label, rows]) => {
        const measured = rows.filter(c => c.mark)
        text(sl, label.toUpperCase(), { x, y, w: w * 0.7, h: 0.3, fontSize: 11, bold: true, color: C.accent2, charSpacing: 1.5, objectName: `${reg.group} ${key} label` })
        const smallRows = measured.filter(c => c.smallSample).length
        text(sl, measured.length ? `${measured.filter(c => c.mark === 'E').length} of ${measured.length}${smallRows ? ` (${smallSampleText(smallRows)})` : ''}` : '', { x: x + w * 0.45, y, w: w * 0.55, h: 0.3, fontSize: 11, bold: true, color: C.accent2, align: 'right', objectName: `${reg.group} ${key} count` })
        rule(sl, x, y + 0.33, w, C.text2, 1, `${reg.group} ${key} rule`)
        y += 0.42
        rows.forEach(c => {
          // A control with a detail line (the ratio behind a Mostly enforced policy, or the resource types a
          // partially covered control is missing) carries it under the label.
          const h = rowLines(c, labelW, size) * lineH(size) + 0.07, chipH = size >= 11 ? 0.26 : 0.22
          markChip(sl, c.chip, x, y + (h - chipH) / 2, 0.36, chipH, size, `${c.label} chip`)
          const runs = [{ text: c.label, options: { fontSize: size, color: C.text1 } }, ...(suffix(c) ? [{ text: suffix(c), options: { fontSize: size - 1, color: C.accent6 } }] : [])]
          if (c.detail) { runs[runs.length - 1].options.breakLine = true; runs.push({ text: c.detail, options: { fontSize: size - 1, color: C.accent6 } }) }
          text(sl, runs.length > 1 ? runs : c.label, { x: x + 0.48, y, w: labelW, h, fontSize: size, color: C.text1, valign: 'middle', objectName: `${c.label} register label` })
          const inline = c.sampleText && sampleInline(c, size)
          const value = c.sampleText ? [{ text: c.valueText, options: { fontSize: size, bold: true, color: C.text2, breakLine: !inline } }, { text: `${inline ? SAMPLE_SEP : ''}${c.sampleText}`, options: { fontSize: size - 1, color: C.accent6 } }] : c.valueText
          text(sl, value, { x: x + w - VALUE_W, y, w: VALUE_W, h, fontSize: size, bold: !!c.mark && !c.sampleText, color: c.mark ? C.text2 : C.accent6, align: 'right', valign: 'middle', objectName: `${c.label} register value` })
          rule(sl, x, y + h + 0.005, w, HEX.track, 0.5, `${c.label} register rule`)
          y += h + 0.01
        })
        y += 0.1
      })
    }
    const regNotes = regs => notesOf(['Reference.', regs.map(r => [...r.foundational, ...r.defense].map(c => `${c.label}: ${c.valueText}${c.exceptionText ? `, ${c.exceptionText}` : ''}${c.sampleText ? `, ${c.sampleText}` : ''}. ${c.note}`))])
    const half = (CW - 0.4) / 2
    ;[[0, 1, 'A1', 'identity and endpoint'], [2, 3, 'A2', 'network and data']].forEach(([a, b, code, name]) => {
      s = content('Appendix', `Control register: ${name}`, `Appendix ${code} · ${legend}`)
      const size = registerSize([st.register[a], st.register[b]], half)
      pillarColumn(s, st.register[a], X0, half, size)
      pillarColumn(s, st.register[b], X0 + half + 0.4, half, size)
      s.addNotes(regNotes([st.register[a], st.register[b]]))
    })
    s = content('Appendix', 'Control register: detection, and how we grade', `Appendix A3 · ${legend}`)
    pillarColumn(s, st.register[4], X0, half, registerSize([st.register[4]], half))
    const gx = X0 + half + 0.4
    text(s, 'How we grade posture', { x: gx, y: TOP - 0.05, w: half, h: 0.4, fontSize: 18, bold: true, color: C.text2, objectName: 'Grading heading' })
    rule(s, gx, TOP + 0.4, half, C.text2, 1, 'Grading rule')
    const bench = m.tiers.benchmark.slice(0, 4).map(r => `${r.label} ${r.value}`).join(' · ')
    const grade = [['Outcomes', 'Did the program hold? Alerts, confirmed threats, response speed.'], ['Control effectiveness', 'What is actually enforced, graded E, P or N. An E that leaves resources out lists its exceptions.'], ['Hardening next', 'Proposed in priority order on the roadmap.'], ['Vendor benchmark, as context', bench || 'Microsoft scores are read as context, never as the objective.']]
    let gy = TOP + 0.55
    grade.forEach(([head, body], i) => {
      const h = 0.3 + lines(body, half - 0.5, 12) * 0.2 + 0.12
      text(s, String(i + 1), { x: gx, y: gy, w: 0.4, h: 0.3, fontSize: 16, bold: true, color: C.accent2, objectName: `Grade ${i + 1} number` })
      text(s, [{ text: head, options: { fontSize: 14, bold: true, color: C.text2, breakLine: true } }, { text: body, options: { fontSize: 12, color: C.accent6, paraSpaceBefore: 2 } }], { x: gx + 0.5, y: gy, w: half - 0.5, h, objectName: `Grade ${i + 1}` })
      gy += h + 0.08
    })
    const dh = Math.min(1.15, BOTTOM - gy - 0.1)
    card(s, gx, gy + 0.1, half, dh, 'Tier definitions card')
    text(s, [{ text: 'Foundational', options: { bold: true, color: C.text2 } }, { text: ' controls are the baseline and should hold at E. Below E is a gap, first on the roadmap.', options: { color: C.text1, breakLine: true } }, { text: 'Defense in depth', options: { bold: true, color: C.text2, paraSpaceBefore: 6 } }, { text: ' controls are layered on top, each waiting on your approval, schedule or license.', options: { color: C.text1 } }], { x: gx + 0.25, y: gy + 0.1, w: half - 0.5, h: dh, fontSize: 12, valign: 'middle', objectName: 'Tier definitions' })
    s.addNotes(notesOf([regNotes([st.register[4]]), 'Posture is reported for the whole tenant, not for Azure resources alone, and never as a single vendor percentage. Vendor benchmark readings are context, not the objective. Microsoft widened what counts as an assessed resource during 2026, so score movement can reflect measurement changes as well as control changes.']))

    // Appendix A4: scope and evidence. What the readings cover, over which period and sources, and the controls
    // this collection could not grade with what each needs. Reasons stay at the category level on the slide.
    s = content('Appendix', 'Scope and evidence', 'Appendix A4 · What the readings cover, and the controls this collection could not grade')
    const gapOf = id => (data.manifest || []).some(r => r.ResultId === id && (r.AccessGap === true || String(r.AccessGap).toLowerCase() === 'true'))
    const retention = [...new Set(m.workspaces.map(w => fmt(w.RetentionDays)))]
    const facts = [
      ['Alert period', m.period.label],
      ['Configuration and scores', `Read ${m.readDate}`],
      ['Identity and endpoint lookbacks', 'Last 30 days. Endpoint sensors and onboarding, last 7 days.'],
      ['Subscriptions in scope', fmt(m.subscriptions)],
      ['Sentinel workspaces', `${fmt(m.workspaces.length)}${retention.length ? `, retention ${list(retention)} days` : ''}`],
      ['Alerts', `${m.ticketed ? 'Sentinel records that opened a ticket with the managed security service. Informational severity is excluded.' : 'Sentinel records triaged by the managed security service.'}${m.xdrScope.sentence ? ' ' + m.xdrScope.sentence : ''}`],
      ['Detections', !m.detections ? 'Records correlated into those alerts. Detection sources are confirmed in the review.' : m.detections.allSources ? `Records from ${m.detections.allSources} correlated into those alerts.` : m.detections.total === 0 ? 'No detection records were correlated into those alerts.' : 'Records correlated into those alerts. Their sources were not recorded.'],
      ['Device measures', 'Azure virtual machines. The Defender for Endpoint and Update Manager measures also count Azure Arc-enabled servers. Trusted Launch, encryption at host and backup read native virtual machines only. Workstations and network appliances stay out.'],
      ['Status marks', 'Read at collection. A control below E is a gap against the baseline, not a change since the last review.']
    ]
    eyebrow(s, 'What the readings cover', X0, TOP - 0.05, half, C.text2, 'Scope')
    rule(s, X0, TOP + 0.3, half, C.text2, 1, 'Scope rule')
    // The facts step down from 11 pt to 9 pt until they end above the content bottom, so a longer scope statement,
    // such as the Defender XDR sentence on the Alerts fact, never runs off the slide (Oct 17, 2026).
    const factHeights = size => facts.map(([, v]) => Math.max(0.28, lines(v, half - 2.4, size) * 0.185 * size / 11 + 0.1))
    const factSize = [11, 10].find(size => factHeights(size).reduce((y, h) => y + h + 0.05, TOP + 0.42) <= BOTTOM) || 9
    const heights = factHeights(factSize)
    let fy = TOP + 0.42
    facts.forEach(([k, v], i) => {
      const h = heights[i]
      text(s, k, { x: X0, y: fy, w: 2.3, h, fontSize: factSize, bold: true, color: C.text2, objectName: `Scope ${i + 1} label` })
      text(s, v, { x: X0 + 2.4, y: fy, w: half - 2.4, h, fontSize: factSize, color: C.text1, objectName: `Scope ${i + 1} value` })
      rule(s, X0, fy + h, half, HEX.track, 0.5, `Scope ${i + 1} rule`)
      fy += h + 0.05
    })
    const ux = X0 + half + 0.4
    eyebrow(s, 'Not graded in this collection', ux, TOP - 0.05, half, C.text2, 'Ungathered')
    rule(s, ux, TOP + 0.3, half, C.text2, 1, 'Ungathered rule')
    const naControls = m.controls.filter(c => c.na)
    const whyOf = c => c.na ? 'No activity or configuration to judge it by' : gapOf(c.id) ? 'Needs read access from your team' : 'Not available from the sources read in this collection'
    const notGraded = [...st.ungathered, ...naControls]
    if (!notGraded.length) text(s, 'Every control was gathered and graded in this collection.', { x: ux, y: TOP + 0.45, w: half, h: 0.4, fontSize: 12, color: C.accent6, objectName: 'Ungathered empty' })
    // One column of entries, then as many continuation slides of two columns as the rest need. Nothing is
    // dropped: a partial collection can leave dozens of controls ungraded. Every column stops above the bottom
    // band, which is kept clear for the "Continued on the next slide" marker, so a wrapped two-line last entry
    // never sits under the marker.
    const BAND = 0.35
    const entryH = c => Math.min(2, lines(c.label, half - 0.5, 11)) * 0.185 + 0.26
    const fillColumn = (sl, x, from, prefix) => {
      let y = TOP + 0.42, i = from
      while (i < notGraded.length) {
        const c = notGraded[i], h = entryH(c)
        if (y + h > BOTTOM - BAND) break
        markChip(sl, c.na ? 'N/A' : '–', x, y + 0.03, 0.36, 0.26, 11, `${prefix} ${i + 1} chip`)
        text(sl, [{ text: c.label, options: { fontSize: 11, color: C.text1, breakLine: true } }, { text: `${whyOf(c)} · ${c.group}`, options: { fontSize: 9.5, color: C.accent6, paraSpaceBefore: 1 } }], { x: x + 0.48, y, w: half - 0.48, h, objectName: `${prefix} ${i + 1}` })
        rule(sl, x, y + h, half, HEX.track, 0.5, `${prefix} ${i + 1} rule`)
        y += h + 0.05
        i++
      }
      return i
    }
    const scopeNotes = notesOf([`Alert activity covers ${m.period.label}. Identity and endpoint readings use the source lookback, generally the last 30 days. Configuration and score readings are from ${m.readDate}.`, `Sentinel workspaces: ${m.workspaces.map(w => `${w.Name}, ${fmt(w.RetentionDays)} days retention`).join('. ')}.`, st.ungathered.length ? `Not gathered: ${st.ungathered.map(c => c.label).join('. ')}.` : 'Every control was gathered.'])
    let next = fillColumn(s, ux, 0, 'Ungathered')
    if (next < notGraded.length) text(s, `Continued on the next slide, ${plural(notGraded.length - next, 'more control', 'more controls')}.`, { x: ux, y: BOTTOM - 0.3, w: half, h: 0.3, fontSize: 10, color: C.accent6, align: 'right', objectName: 'Ungathered continued' })
    s.addNotes(scopeNotes)
    for (let page = 2; next < notGraded.length; page++) {
      s = content('Appendix', 'Scope and evidence, continued', `Appendix A4 · Controls this collection could not grade, continued`)
      eyebrow(s, 'Not graded in this collection', X0, TOP - 0.05, CW, C.text2, `Ungathered page ${page}`)
      rule(s, X0, TOP + 0.3, CW, C.text2, 1, `Ungathered page ${page} rule`)
      next = fillColumn(s, X0, next, `Ungathered page ${page} left`)
      if (next < notGraded.length) next = fillColumn(s, ux, next, `Ungathered page ${page} right`)
      if (next < notGraded.length) text(s, `Continued on the next slide, ${plural(notGraded.length - next, 'more control', 'more controls')}.`, { x: ux, y: BOTTOM - 0.3, w: half, h: 0.3, fontSize: 10, color: C.accent6, align: 'right', objectName: `Ungathered page ${page} continued` })
      s.addNotes(scopeNotes)
    }
  }

  // Appendix A4 and A5, Detailed only: the two Microsoft scores and where the next points are.
  if (detailed) {
    const stat = (sl, x, y, w, h, value, label, sub, name, size = 34) => {
      card(sl, x, y, w, h, `${name} card`)
      text(sl, [{ text: value, options: { fontSize: size, bold: true, color: C.accent2, breakLine: true } }, { text: label, options: { fontSize: 15, bold: true, color: C.text2, breakLine: !!sub, paraSpaceBefore: 4 } }, ...(sub ? [{ text: sub, options: { fontSize: 12, color: C.accent6, paraSpaceBefore: 4 } }] : [])], { x: x + 0.3, y: y + 0.25, w: w - 0.6, h: h - 0.4, objectName: name })
    }
    s = content('Appendix', 'Tenant and cloud security posture', 'Appendix A5 · Microsoft calculates both scores. We report them as context, not as the objective.')
    const cw2 = (CW - 0.3) / 2, ch2 = 2.95
    // Each score reads as a percentage with its movement in percentage points, never as points available. The
    // Defender for Cloud card draws the score by month as the HTML page does, and the tenant card adds the
    // category scores (Oct 14, 2026).
    const scoreCard = (x, eye, score, body, name, trend = null) => {
      card(s, x, TOP, cw2, ch2, `${name} card`)
      text(s, eye, { x: x + 0.3, y: TOP + 0.2, w: cw2 - 0.6, h: 0.3, fontSize: 11, bold: true, color: C.accent2, charSpacing: 1.5, objectName: `${name} eyebrow` })
      const chartW = trend ? 3.1 : 2.25
      if (trend) {
        const values = trend.map(t => t.pct), lo = Math.max(0, Math.floor((Math.min(...values) - 4) / 5) * 5), hi = Math.min(100, Math.ceil((Math.max(...values) + 4) / 5) * 5)
        s.addChart(pres.charts.LINE, [{ name: 'Score', labels: trend.map(t => t.label), values }], {
          x: x + 0.15, y: TOP + 0.5, w: chartW, h: ch2 - 0.6, lineSize: 2.5, lineDataSymbol: 'circle', lineDataSymbolSize: 7, chartColors: [HEX.accent2],
          valAxisMinVal: lo, valAxisMaxVal: hi, valAxisLabelFontSize: 9, valAxisLabelColor: HEX.accent6, valAxisLabelFontFace: '+mn-lt', valAxisLabelFormatCode: '0"%"', valGridLine: { color: HEX.track, size: 0.5 },
          catAxisLabelFontSize: 9, catAxisLabelColor: HEX.dk1, catAxisLabelFontFace: '+mn-lt', catGridLine: { style: 'none' }, showLegend: false,
          showValue: trend.length <= 6, dataLabelPosition: 't', dataLabelFontSize: 9, dataLabelFontBold: true, dataLabelColor: HEX.dk2, dataLabelFontFace: '+mn-lt', dataLabelFormatCode: '0.0"%"', objectName: `${name} chart`
        })
      } else if (score !== null) {
        s.addChart(pres.charts.DOUGHNUT, [{ name, labels: ['Score', 'Remaining'], values: [score, Math.max(0, 100 - score)] }], { x: x + 0.25, y: TOP + 0.55, w: 2.25, h: 2.25, holeSize: 72, chartColors: [HEX.accent2, HEX.track], showLegend: false, showValue: false, showPercent: false, showLabel: false, showTitle: false, objectName: `${name} chart` })
        text(s, pctText(score), { x: x + 0.25, y: TOP + 1.37, w: 2.25, h: 0.6, fontSize: 22, bold: true, color: C.text2, align: 'center', valign: 'middle', objectName: `${name} value` })
      }
      const tx = x + (score !== null ? chartW + 0.55 : 0.3), tw = cw2 - (score !== null ? chartW + 0.85 : 0.6)
      text(s, body, { x: tx, y: TOP + 0.6, w: tw, h: ch2 - 0.8, fontSize: 12, color: C.text1, valign: 'top', objectName: `${name} text` })
      return { tx, tw }
    }
    const movement = (sc, color) => ({ text: sc.delta && sc.delta.points > 0 ? `Up ${fmt(sc.delta.points)} points since ${sc.delta.since}, from ${pctText(sc.delta.from)}.` : 'Reported as current state.', options: { bold: !!(sc.delta && sc.delta.points > 0), color: sc.delta && sc.delta.points > 0 ? C.accent3 : color, breakLine: true, paraSpaceBefore: 4 } })
    const cs = m.cloudScore
    const cloudTrend = cs && cs.trend.length >= 2 ? cs.trend : null
    scoreCard(X0, 'DEFENDER FOR CLOUD · AZURE RESOURCE ESTATE', cs ? cs.value : null, cs ? [
      { text: pctText(cs.value), options: { fontSize: 24, bold: true, color: C.text2, breakLine: true } },
      movement(cs, C.accent6),
      // The assessed resource count is the inventory card below, so the card text carries the model, scope and read.
      { text: cs.basis, options: { fontSize: 11, color: C.accent6, paraSpaceBefore: 4 } }
    ] : 'Reading completed in the review.', 'Defender for Cloud', cloudTrend)
    const tsc = m.tenantScore
    const tenantBox = scoreCard(X0 + cw2 + 0.3, 'MICROSOFT SECURE SCORE · MICROSOFT 365 TENANT', tsc ? tsc.value : null, tsc ? [
      { text: pctText(tsc.value), options: { fontSize: 24, bold: true, color: C.text2, breakLine: true } },
      movement(tsc, C.accent6),
      { text: tsc.basis, options: { fontSize: 11, color: C.accent6, paraSpaceBefore: 4 } }
    ] : [{ text: 'Added from the portal reading', options: { fontSize: 18, bold: true, color: C.text2, breakLine: true } }, { text: 'The tenant score is read in the Defender portal and added through the review context so both estates are presented together.', options: { paraSpaceBefore: 6 } }], 'Secure Score')
    if (tsc && tsc.categories.length) {
      // Category scores under the reading, as the HTML card shows them, starting below the measured text: the
      // percentage, the movement line and the model line at their sizes, with 4 pt between paragraphs. The model
      // line is given one extra line, since renderers wrap with different font metrics.
      const movementText = movement(tsc, C.accent6).text
      const need = 24 / 72 * 1.2 + (lines(movementText, tenantBox.tw, 12, !!tsc.delta) * 12 + (lines(tsc.basis, tenantBox.tw, 11) + 1) * 11) / 72 * 1.2 + 8 / 72
      let cy = Math.max(TOP + 1.85, TOP + 0.6 + need + 0.05)
      const rowH = Math.min(0.24, (TOP + ch2 - 0.05 - cy) / tsc.categories.length)
      tsc.categories.forEach((c, i) => {
        text(s, c.label, { x: tenantBox.tx, y: cy, w: 0.85, h: rowH, fontSize: 9.5, color: C.text1, valign: 'middle', objectName: `Category ${i + 1} label` })
        meter(s, tenantBox.tx + 0.9, cy + (rowH - 0.14) / 2, tenantBox.tw - 1.55, c.pct, C.accent2, `Category ${i + 1}`)
        text(s, pctText(c.pct), { x: tenantBox.tx + tenantBox.tw - 0.6, y: cy, w: 0.6, h: rowH, fontSize: 9.5, bold: true, color: C.text2, align: 'right', valign: 'middle', objectName: `Category ${i + 1} value` })
        cy += rowH
      })
    }
    const inv = [[fmt(m.posture.estate), 'Azure resources in the estate', m.excluded ? `Managed resource groups matching ${m.excluded} are excluded.` : 'No managed resource group exclusion was configured.'], [fmt(m.posture.assessed), 'Resources assessed by Defender for Cloud', 'Distinct resources in assessment records at collection.'], m.posture.rules ? [fmt(m.posture.rules.enabled), 'Analytics rules active in Sentinel', `Of ${fmt(m.posture.rules.total)} rules across ${plural(m.workspaces.length, 'workspace', 'workspaces')}.`] : [fmt(m.posture.telemetryTables), 'Telemetry tables collected', 'Distinct data types reaching the workspaces.']]
    const iw = (CW - 0.6) / 3, iy = TOP + ch2 + 0.3
    inv.forEach(([v, l, sub], i) => stat(s, X0 + i * (iw + 0.3), iy, iw, BOTTOM - iy, v, l, sub, `Inventory ${i + 1}`))
    s.addNotes(notesOf(['Microsoft calculates both scores. We report them as benchmark and context, and we do not manage the environment to them.', `Tenant-wide sign-in readings use ${m.tenantWorkspace}. Alert metrics come from one combined query across the workspaces, and workspace medians and distinct counts are never added together.`, `Sentinel workspaces: ${m.workspaces.map(w => `${w.Name}, ${fmt(w.RetentionDays)} days retention`).join('. ')}.`]))

    s = content('Appendix', 'Where the next points are', 'Appendix A6 · Microsoft score controls ranked by the points still available')
    const sc = m.posture.scoreControls.slice(0, 8), leftW = 7.3
    if (sc.length) s.addChart(pres.charts.BAR, [{ name: 'Score control', labels: sc.map(c => `${c.label} (${fmt(c.remaining)} ${c.remaining === 1 ? 'pt' : 'pts'}${c.resources ? `, ${fmt(c.healthy)} of ${fmt(c.resources)} healthy` : ''})`), values: sc.map(c => c.pct) }], {
      x: X0, y: TOP, w: leftW, h: BOTTOM - TOP, barDir: 'bar', chartColors: [HEX.accent2], barGapWidthPct: 40, valAxisMinVal: 0, valAxisMaxVal: 100, valAxisHidden: true,
      showValue: true, dataLabelPosition: 'outEnd', dataLabelColor: HEX.dk1, dataLabelFontSize: 11, dataLabelFontFace: '+mn-lt', dataLabelFormatCode: '0.0"%"',
      catAxisOrientation: 'maxMin', catAxisLabelColor: HEX.dk1, catAxisLabelFontSize: 11, catAxisLabelFontFace: '+mn-lt',
      valGridLine: { style: 'none' }, catGridLine: { style: 'none' }, showLegend: false, showTitle: true, title: 'Share of each score control earned', titleFontSize: 14, titleColor: HEX.dk2, titleFontFace: '+mn-lt', objectName: 'Score controls chart'
    })
    else emptyCard(s, 'Score control detail is reviewed in the portal.', 'Score controls')
    const rx = X0 + leftW + 0.3, rw = CW - leftW - 0.3
    const meters = [m.posture.highHealthy ? ['High severity assessments healthy', `${fmt(m.posture.highHealthy.good)} of ${fmt(m.posture.highHealthy.total)}`, m.posture.highHealthy.pct] : null, m.posture.benchmark ? ['Microsoft cloud security benchmark controls passed', `${fmt(m.posture.benchmark.passed)} of ${fmt(m.posture.benchmark.total)}`, m.posture.benchmark.pct] : null].filter(Boolean)
    let my = TOP
    meters.forEach(([l, v, pct], i) => {
      card(s, rx, my, rw, 1.35, `Meter ${i + 1} card`)
      text(s, [{ text: l, options: { fontSize: 13, bold: true, color: C.text2, breakLine: true } }, { text: `${v} · ${pctText(pct)}`, options: { fontSize: 13, color: C.accent6, paraSpaceBefore: 2 } }], { x: rx + 0.25, y: my + 0.15, w: rw - 0.5, h: 0.75, objectName: `Meter ${i + 1}` })
      meter(s, rx + 0.25, my + 1.0, rw - 0.5, pct, C.accent2, `Meter ${i + 1}`)
      my += 1.55
    })
    card(s, rx, my, rw, BOTTOM - my, 'Explainer card', C.text2)
    text(s, [{ text: 'MICROSOFT CHANGED HOW SECURE SCORE IS CALCULATED', options: { fontSize: 10, bold: true, color: C.accent1, charSpacing: 1, breakLine: true } }, { text: 'A score movement can reflect a change in the measurement model, the scope or the weighting rather than a change in your controls. We track the controls behind the score, not the percentage alone.', options: { fontSize: 13, color: C.background1, paraSpaceBefore: 6 } }], { x: rx + 0.25, y: my + 0.2, w: rw - 0.5, h: BOTTOM - my - 0.35, objectName: 'Explainer' })
    s.addNotes(notesOf([m.posture.scoreControlBasis, st.headroom]))
  }

  console.log(await writeDeck(pres, path.resolve(outFile)))
}

main().catch(e => { console.error(e.message || e); process.exit(1) })
