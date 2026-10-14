/* PowerPoint edition of the EBR security report (03-security-report.pptx), written by
   New-EbrSecurityReport.ps1 beside the HTML. It reads the same embedded data and runs the same report
   model, then the story layer (report-story.js) for the wins, decisions, drift and roadmap.

   Structure (docs/plans/2026-10-12-ebr-deck-restructure-design.md, grounding slides added Oct 14, 2026):
   cover, executive summary, wins, security operations, confirmed threats (only when there are examples),
   control posture, measured outcomes by pillar, hardening roadmap, priority workstreams, passwordless
   transition, decisions needed, then the appendix: the control register, scope and evidence. Brief keeps
   the cover, summary, wins, roadmap, passwordless and decisions. Detailed adds the two Microsoft score
   slides to the appendix.

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
const { build, fmt, clean, pctText, plural } = require('./report-model.js')
const { buildStory } = require('./report-story.js')

const [dataFile, outFile] = process.argv.slice(2)
if (!dataFile || !outFile) { console.error('usage: node build-report-deck.cjs <data.json> <output.pptx>'); process.exit(2) }
const data = JSON.parse(fs.readFileSync(dataFile, 'utf8').replace(/^﻿/, ''))
const m = build(data)
const st = buildStory(m, data)

const TOP = 1.75, BOTTOM = 7.0
const balanced = m.depth !== 'brief', detailed = m.depth === 'detailed'
const notesOf = parts => parts.flat(3).map(clean).filter(Boolean).join('\n\n')
const sentence = t => { const v = clean(t); return v ? v.charAt(0).toUpperCase() + v.slice(1) : '' }
const list = items => items.length <= 1 ? items.join('') : `${items.slice(0, -1).join(', ')} and ${items[items.length - 1]}`
const scopeMeta = `Posture read ${m.readDate} · ${plural(m.subscriptions, 'subscription', 'subscriptions')} · ${plural(m.workspaces.length, 'Sentinel workspace', 'Sentinel workspaces')}`

async function main() {
  const { pres, C, card, chip, text, meter, markFill, rule, glue } = createDeck({ title: `${m.client} | Security business review` })
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

  // 1. Cover
  pres.addSection({ title: 'Summary' })
  let s = pres.addSlide({ masterName: 'Atmosera Title', sectionTitle: 'Summary' })
  s.addText('MANAGED SECURITY SERVICES · EXECUTIVE BUSINESS REVIEW', { placeholder: 'eyebrow' })
  s.addText('Security business review', { placeholder: 'title' })
  s.addText(m.client, { placeholder: 'subtitle' })
  s.addText(st.quarter ? `${st.quarter} · ${m.period.label}` : m.period.label, { placeholder: 'caption' })
  s.addText(scopeMeta, { placeholder: 'meta' })
  s.addNotes(notesOf([`Security business review for ${m.client}.`, `Alert activity covers ${m.period.label}. Identity and endpoint readings use the source lookback, generally the last 30 days. Configuration and score readings are from ${m.readDate}.`]))

  // 2. Executive summary: outcome KPIs, then wins, watch and decisions.
  s = content('Summary', 'Executive summary', st.takeaways.summary)
  if (st.kpis.length) {
    const n = st.kpis.length, w = CW / n
    rule(s, X0, TOP - 0.05, CW, C.text2, 1, 'KPI top rule')
    st.kpis.forEach((k, i) => {
      const x = X0 + i * w
      if (i) s.addShape(pres.shapes.LINE, { x, y: TOP + 0.05, w: 0, h: 1.8, line: { color: HEX.track, width: 0.75 }, objectName: `KPI divider ${i}` })
      text(s, [{ text: k.value, options: { fontSize: 38, bold: true, color: C.accent2, breakLine: true } }, { text: k.label, options: { fontSize: 15, bold: true, color: C.text2, breakLine: true, paraSpaceBefore: 2 } }, { text: k.sub, options: { fontSize: 12, color: C.accent6, paraSpaceBefore: 3 } }], { x: x + (i ? 0.3 : 0), y: TOP + 0.08, w: w - 0.45, h: 1.8, objectName: `KPI ${i + 1}` })
    })
    rule(s, X0, TOP + 1.98, CW, HEX.track, 0.75, 'KPI bottom rule')
  }
  const colW = (CW - 0.8) / 3, colY = TOP + 2.2
  ;[['Wins', C.accent3, st.summaryWins, 'Readings are completed in the review.'], ['Watch', C.accent4, st.watch, 'Nothing on the watch list from this collection.'], ['Decisions needed', C.text2, st.summaryAsks, 'No approvals or access needed before the next review.']].forEach(([label, color, items, empty], i) => {
    const x = X0 + i * (colW + 0.4)
    eyebrow(s, label, x, colY, colW, C.text2, `Summary ${label}`)
    rule(s, x, colY + 0.38, colW, color, 2.5, `Summary ${label} rule`)
    if (!items.length) { text(s, empty, { x, y: colY + 0.55, w: colW, h: 0.5, fontSize: 13, color: C.accent6, objectName: `Summary ${label} empty` }); return }
    let y = colY + 0.52
    items.forEach((it, n) => {
      const h = 0.34 + lines(it.label, colW, 13) * 0.21 + 0.08
      text(s, [{ text: it.value, options: { fontSize: 18, bold: true, color: C.text2, breakLine: true } }, { text: it.label, options: { fontSize: 13, color: C.text1 } }], { x, y, w: colW, h, objectName: `Summary ${label} ${n + 1}` })
      y += h
    })
  })
  s.addNotes(notesOf(['Lead with outcomes.', st.takeaways.summary, st.kpis.map(k => `${k.label}: ${k.value}. ${k.sub}.`), 'Then the watch list, and the decisions we will ask for at the close.']))

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
      s.addChart(pres.charts.BAR, sev.map(k => ({ name: k, labels: trendRows.map(r => r.label), values: trendRows.map(r => r[k]) })), {
        x: q.x - 0.1, y: q.y - 0.05, w: qw + 0.1, h: q.h, barDir: 'col', barGrouping: 'stacked', barGapWidthPct: trendRows.length > 6 ? 45 : 90,
        chartColors: sev.map(k => colors[k]), catAxisLabelColor: HEX.dk1, catAxisLabelFontSize: 11, catAxisLabelFontFace: '+mn-lt', valAxisLabelColor: HEX.accent6, valAxisLabelFontSize: 10, valAxisLabelFontFace: '+mn-lt',
        valGridLine: { color: HEX.track, size: 0.5 }, catGridLine: { style: 'none' }, showLegend: true, legendPos: 'r', legendFontSize: 11, legendFontFace: '+mn-lt', legendColor: HEX.dk1, objectName: 'Monthly alerts chart'
      })
    } else text(s, 'Monthly volume is confirmed in the review.', { x: q.x, y: q.y, w: qw, h: 0.4, fontSize: 13, color: C.accent6, objectName: 'Monthly alerts empty' })
    // Time to close by severity. Medians under the floor are never shown.
    q = quad(1, 'Time to close, by severity')
    if (m.timing && m.timing.length) {
      const head = ['Severity', 'Closed', 'Median', '90% within'].map((t, i) => ({ text: t, options: { fontSize: 11, color: HEX.accent6, align: i ? 'right' : 'left', border: border(0.75) } }))
      const body = m.timing.map(r => {
        const all = r.scope === 'All', fill = all ? { color: HEX.lt2 } : undefined
        const cell = (t, o = {}) => ({ text: t, options: { fontSize: 13, color: HEX.dk1, align: 'right', fill, border: border(0.5), ...o } })
        return [cell(all ? 'All closed' : r.scope, { bold: true, color: HEX.dk2, align: 'left' }), cell(fmt(r.n)), cell(r.median ? r.median.value : '–', { bold: true, color: r.median ? HEX.accent2 : HEX.accent6 }), cell(r.p90 ? r.p90.value : '–')]
      })
      s.addTable([head, ...body], { x: q.x, y: q.y - 0.05, w: qw, colW: [qw * 0.34, qw * 0.2, qw * 0.21, qw * 0.25], rowH: 0.34, margin: [0.03, 0.08, 0.03, 0.08], objectName: 'Time to close table' })
      text(s, 'Medians under 20 minutes are not presented. 90% within is the 90th percentile.', { x: q.x, y: q.y + 0.34 * (body.length + 1) + 0.05, w: qw, h: 0.3, fontSize: 10, color: C.accent6, objectName: 'Time to close caption' })
    } else text(s, 'Response timing is confirmed in the review.', { x: q.x, y: q.y, w: qw, h: 0.4, fontSize: 13, color: C.accent6, objectName: 'Time to close empty' })
    // How closed alerts were resolved. Open alerts appear only as the referral sentence.
    q = quad(2, 'How closed alerts were resolved')
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
      if (a.open > 0) text(s, `${fmt(a.open)} more ${a.open === 1 ? 'is' : 'are'} referred to your team for action or confirmation under the agreed notification process, or still in progress.`, { x: q.x, y: ly + 0.42, w: qw, h: 0.65, fontSize: 12, color: C.accent6, objectName: 'Referral note' })
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
      m.ticketed ? 'An alert is a Sentinel record that opened a ticket with the managed security service. Informational severity is excluded, and detections are the records correlated into those alerts.' : 'Detections from Sentinel, Defender for Cloud and the Defender services are correlated into alerts.',
      m.alerts ? `Closed alerts: ${fmt(m.alerts.benign)} benign positive, ${fmt(m.alerts.falsePositives)} false positive, ${fmt(m.alerts.truePositives)} true positive, ${fmt(m.alerts.unclassified)} unclassified.` : '',
      m.alerts && m.alerts.open > 0 ? 'The remaining alerts are referred to your team for action or confirmation under the agreed notification process, or are still under investigation.' : '',
      'Response times run from alert creation to recorded close. Medians under 20 minutes are not presented, so the 90th percentile carries the speed story where the median is faster.'
    ]))

    // 4b. Confirmed threats: up to five examples, highest severity first. Omitted when there are none.
    if (m.threats) {
      s = content('Operations and posture', 'Confirmed threats', st.takeaways.threats)
      const HEAD_H = 0.4, GAP = 0.2, CAPTION_H = 0.35, PAD_X = 0.1
      const colW = [CW * 0.38, CW * 0.09, CW * 0.11, CW * 0.2, CW * 0.22]
      const head = ['Threat', 'Alerts', 'Severity', 'Attack stage', 'When'].map((t, i) => ({ text: t, options: { fontSize: 12, color: HEX.accent6, align: i === 1 ? 'right' : 'left', border: border(0.75) } }))
      // Rows hold two lines and grow for a longer title or stage, so the caption stays below the table. When the rows
      // would push the caption past BOTTOM, the body drops to 12 pt. If that is still too tall, long titles are cut at
      // a word before 110 characters and end in three dots.
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
      text(s, `${m.threats.more ? `And ${plural(m.threats.moreAlerts, 'more confirmed alert', 'more confirmed alerts')} in ${plural(m.threats.more, 'further group', 'further groups')}. ` : ''}Confirmed as true positives by the SOC and closed, grouped by alert title.`, { x: X0, y: TOP + HEAD_H + fit.height + GAP, w: CW, h: CAPTION_H, fontSize: 11, color: C.accent6, objectName: 'Confirmed threats caption' })
      s.addNotes(notesOf([
        'These are alerts the SOC confirmed as true positive threats, grouped by alert title, highest severity first.',
        m.ticketed ? 'Each one opened a ticket with the managed security service and was closed by the SOC.' : '',
        st.takeaways.threats
      ]))
    }

    // 5. Control posture: pillar matrix and the foundational drift panel.
    s = content('Operations and posture', 'Control posture', st.takeaways.posture)
    const mw = 7.85, cols = [1.95, 1.45, 1.45, mw - 4.85]
    const cx = [X0, X0 + cols[0], X0 + cols[0] + cols[1], X0 + cols[0] + cols[1] + cols[2]]
    ;['Pillar', 'Foundational', 'Defense in depth', 'Headline measure'].forEach((h, i) => text(s, h, { x: cx[i], y: TOP, w: cols[i] - 0.15, h: 0.45, fontSize: 12, bold: true, color: C.accent6, valign: 'bottom', objectName: `Matrix header ${i + 1}` }))
    rule(s, X0, TOP + 0.52, mw, C.text2, 1, 'Matrix header rule')
    const rh = 0.74
    st.matrix.forEach((r, i) => {
      const y = TOP + 0.6 + i * rh
      text(s, r.group, { x: cx[0], y, w: cols[0] - 0.15, h: rh - 0.08, fontSize: 15, bold: true, color: C.text2, valign: 'middle', objectName: `${r.group} name` })
      ;[[r.foundational, 1, r.foundational.measured && r.foundational.enforced === r.foundational.measured ? C.accent3 : C.accent4], [r.defense, 2, C.accent2]].forEach(([t, col, fill]) => {
        const tier = col === 1 ? 'foundational' : 'defense'
        text(s, t.measured ? `${t.enforced} of ${t.measured}` : 'Not measured', { x: cx[col], y: y + 0.1, w: cols[col] - 0.2, h: 0.32, fontSize: t.measured ? 15 : 12, bold: !!t.measured, color: t.measured ? C.text2 : C.accent6, objectName: `${r.group} ${tier} count` })
        if (t.measured) meter(s, cx[col], y + 0.47, cols[col] - 0.25, t.pct, fill, `${r.group} ${tier}`)
      })
      text(s, r.measure || 'Readings completed in the review', { x: cx[3], y, w: cols[3], h: rh - 0.08, fontSize: 12, color: C.text1, valign: 'middle', objectName: `${r.group} measure` })
      if (i < st.matrix.length - 1) rule(s, X0, y + rh - 0.02, mw, HEX.track, 0.75, `${r.group} rule`)
    })
    const ay = TOP + 0.6 + st.matrix.length * rh + 0.05
    card(s, X0, ay, mw, BOTTOM - ay, 'All pillars card')
    text(s, 'All pillars', { x: cx[0] + 0.15, y: ay, w: cols[0], h: BOTTOM - ay, fontSize: 15, bold: true, color: C.text2, valign: 'middle', objectName: 'All pillars name' })
    text(s, st.foundational.measured ? `${st.foundational.enforced} of ${st.foundational.measured}` : '–', { x: cx[1], y: ay, w: cols[1], h: BOTTOM - ay, fontSize: 20, bold: true, color: C.accent2, valign: 'middle', objectName: 'All pillars foundational' })
    text(s, st.defense.measured ? `${st.defense.enforced} of ${st.defense.measured}` : '–', { x: cx[2], y: ay, w: cols[2], h: BOTTOM - ay, fontSize: 20, bold: true, color: C.accent2, valign: 'middle', objectName: 'All pillars defense' })
    text(s, st.ungathered.length ? `${plural(st.ungathered.length, 'more control', 'more controls')} not gathered. See the appendix.` : 'Every control was gathered in this collection.', { x: cx[3], y: ay, w: cols[3] - 0.1, h: BOTTOM - ay, fontSize: 12, color: C.accent6, valign: 'middle', objectName: 'All pillars note' })
    // Drift panel.
    const px = X0 + mw + 0.4, pw = CW - mw - 0.4
    card(s, px, TOP, pw, BOTTOM - TOP, 'Drift panel')
    text(s, [{ text: 'Foundational gaps', options: { fontSize: 18, bold: true, color: C.text2, breakLine: true } }, { text: st.drift.length ? 'Below the baseline at collection. Atmosera schedules each fix first.' : st.licensed.length ? 'Every foundational control Atmosera can fix reads E. The one below needs licensing.' : 'No foundational gaps. Every measured foundational control reads E.', options: { fontSize: 12, color: C.accent6, paraSpaceBefore: 4 } }], { x: px + 0.3, y: TOP + 0.25, w: pw - 0.6, h: 1.0, objectName: 'Drift heading' })
    let dy = TOP + 1.1
    // Each item takes the lines its label and figure line need. Items stop above the legend and the tail line
    // (the gaps left in the register, and any control that needs a license), so nothing overlaps.
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
    const tail = [
      st.drift.length > shown.length ? `${plural(st.drift.length - shown.length, 'more foundational gap is', 'more foundational gaps are')} in the register.` : '',
      st.licensed.length ? `${sentence(list(st.licensed.map(c => c.short)))} ${st.licensed.length === 1 ? 'needs' : 'need'} licensing and ${st.licensed.length === 1 ? 'sits' : 'sit'} in Later.` : ''
    ].filter(Boolean).join(' ')
    if (tail) text(s, tail, { x: px + 0.3, y: tailTop, w: pw - 0.6, h: 0.6, fontSize: 11, color: C.accent6, valign: 'bottom', objectName: 'Drift tail' })
    text(s, 'E enforced, 90% or more · P partial, 50 to 89% · N not yet enforced, below 50%', { x: px + 0.3, y: BOTTOM - 0.55, w: pw - 0.6, h: 0.42, fontSize: 11, color: C.accent6, objectName: 'Mark legend' })
    s.addNotes(notesOf([
      'Foundational controls are the baseline the service holds every environment to, and each is expected to read enforced at every review. One that reads below E is a gap against that baseline. Atmosera owns the fix and sets a fix date at this review, and it is first on the roadmap. Defense in depth controls are layered on top, and each waits on something your team approves, schedules or licenses. Every reading describes the state at collection, not a change since the last review.',
      'E means 90 percent or more of in-scope resources, P 50 to 89 percent and N below 50 percent.',
      st.ungathered.length ? `${plural(st.ungathered.length, 'control', 'controls')} could not be graded from the collected evidence and ${st.ungathered.length === 1 ? 'is' : 'are'} listed in the appendix.` : '',
      m.pillars.map(p => `${p.name}. ${p.headline}. ${p.narrative}`)
    ]))

    // 5b. Measured outcomes by pillar: the headline each pillar earned, the narrative behind it, the lead
    // measure and the callout, as the HTML pillar page shows them. A narrative that would not fit its row is
    // cut at a sentence end, and the full text goes to the speaker notes.
    if (m.pillars.length) {
      s = content('Operations and posture', 'Measured outcomes by pillar', st.takeaways.pillars)
      const prow = (BOTTOM - TOP) / m.pillars.length, nameW = 1.9, storyX = X0 + nameW + 0.2, storyW = 6.3, measX = storyX + storyW + 0.3, measW = CW - nameW - 0.2 - storyW - 0.3
      const sentences = t => clean(t).split(/(?<=\.)\s+(?=[A-Z0-9])/).filter(Boolean)
      m.pillars.forEach((p, i) => {
        const y = TOP + i * prow
        if (i) rule(s, X0, y - 0.04, CW, HEX.track, 0.75, `${p.name} outcome rule`)
        const reg = st.matrix.find(r => r.group === p.name)
        text(s, [{ text: p.name, options: { fontSize: 14, bold: true, color: C.text2, breakLine: true } }, { text: reg && reg.foundational.measured ? `${reg.foundational.enforced} of ${reg.foundational.measured} foundational enforced` : 'Readings completed in the review', options: { fontSize: 10, color: C.accent6, paraSpaceBefore: 3 } }], { x: X0, y: y + 0.06, w: nameW, h: prow - 0.12, objectName: `${p.name} outcome name` })
        const room = prow - 0.14, headH = lines(p.headline, storyW, 11, true) * 0.18
        let parts = sentences(p.narrative), body = parts.join(' ')
        while (parts.length > 1 && headH + lines(body, storyW, 10) * 0.165 + 0.05 > room) { parts = parts.slice(0, -1); body = parts.join(' ') }
        text(s, [{ text: p.headline, options: { fontSize: 11, bold: true, color: C.text2, breakLine: true } }, { text: body, options: { fontSize: 10, color: C.text1, paraSpaceBefore: 3 } }], { x: storyX, y: y + 0.06, w: storyW, h: prow - 0.12, objectName: `${p.name} outcome story` })
        if (p.measure) {
          text(s, p.measure.label, { x: measX, y: y + 0.06, w: measW, h: 0.22, fontSize: 10, color: C.accent6, objectName: `${p.name} measure label` })
          meter(s, measX, y + 0.36, measW - 1.15, p.measure.pct, p.measure.mark === 'E' ? C.accent3 : p.measure.mark === 'N' ? C.accent4 : C.accent2, `${p.name} outcome`)
          text(s, `${fmt(p.measure.good)} of ${fmt(p.measure.total)}`, { x: measX + measW - 1.1, y: y + 0.26, w: 1.1, h: 0.32, fontSize: 13, bold: true, color: C.text2, align: 'right', valign: 'middle', objectName: `${p.name} measure value` })
        }
        if (p.callout) text(s, [{ text: p.callout.value, options: { fontSize: 14, bold: true, color: C.accent2 } }, { text: `  ${p.callout.label}`, options: { fontSize: 10, color: C.accent6 } }], { x: measX, y: y + (p.measure ? 0.64 : 0.08), w: measW, h: 0.4, valign: 'middle', objectName: `${p.name} callout` })
      })
      s.addNotes(notesOf(['Each pillar leads with the statement its strongest measure earned. The pillars that read lower need change inside the environment, and each of those items is sequenced on the roadmap.', m.pillars.map(p => `${p.name}. ${p.headline}. ${p.narrative} Evidence ${p.source}`)]))
    }
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
  s.addNotes(notesOf([`Priorities reflect the evidence collected ${m.readDate}. Horizons are proposed for agreement today. Every enforcement is staged in audit or report-only mode, reviewed with your team, then turned on.`,
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

  // 7. Passwordless transition
  const pwd = m.passwordless && m.passwordless.retiring > 0 ? m.passwordless : null
  if (pwd) {
    s = content('Roadmap and decisions', 'Passwordless transition', st.takeaways.passwordless)
    const lw = 6.1
    if (st.deadlineDays !== null && st.deadlineDays > 0) {
      text(s, fmt(st.deadlineDays), { x: X0 - 0.05, y: TOP - 0.15, w: 2.6, h: 1.25, fontSize: 80, bold: true, color: C.accent2, valign: 'middle', objectName: 'Countdown' })
      text(s, [{ text: 'days to the deadline', options: { fontSize: 18, bold: true, color: C.text2, breakLine: true } }, { text: `From ${st.readShort} to ${st.deadlineShort}`, options: { fontSize: 12, color: C.accent6, paraSpaceBefore: 2 } }], { x: X0 + 2.6, y: TOP + 0.35, w: lw - 2.6, h: 0.8, objectName: 'Countdown label' })
    } else text(s, [{ text: fmt(pwd.retiring), options: { fontSize: 60, bold: true, color: C.accent2, breakLine: true } }, { text: 'users still sign in with text message or voice', options: { fontSize: 16, bold: true, color: C.text2 } }], { x: X0, y: TOP, w: lw, h: 1.3, objectName: 'Retiring users' })
    rule(s, X0, TOP + 1.4, lw, C.text2, 1, 'Methods rule')
    eyebrow(s, 'Users by sign-in method, last 30 days', X0, TOP + 1.55, lw, C.text2, 'Methods')
    const methods = [['Authenticator or OTP', pwd.authenticator, C.accent2], ['Text message or voice', pwd.retiring, C.accent4], ['Phishing-resistant', pwd.resistant, C.accent3]]
    const maxM = Math.max(1, ...methods.map(([, v]) => v))
    methods.forEach(([l, v, c], i) => {
      const y = TOP + 2.05 + i * 0.5
      text(s, l, { x: X0, y, w: 2.3, h: 0.35, fontSize: 13, bold: i === 1, color: C.text1, valign: 'middle', objectName: `Method ${i + 1} label` })
      if (v > 0) s.addShape(pres.shapes.RECTANGLE, { x: X0 + 2.35, y: y + 0.07, w: Math.max(0.05, 3.0 * v / maxM), h: 0.22, fill: { color: c }, line: { color: c, width: 0 }, objectName: `Method ${i + 1} bar` })
      text(s, fmt(v), { x: X0 + lw - 0.75, y, w: 0.75, h: 0.35, fontSize: 14, bold: true, color: C.text2, align: 'right', valign: 'middle', objectName: `Method ${i + 1} value` })
    })
    if (pwd.authenticator > 0) text(s, `A passkey can be issued inside the Authenticator app ${plural(pwd.authenticator, 'user already carries', 'users already carry')}.`, { x: X0, y: TOP + 3.65, w: lw, h: 0.4, fontSize: 12, color: C.accent6, objectName: 'Methods caption' })
    const steps = [['Enable passkeys', 'Under change control, inside the app users already carry.'], ['Register in waves', `The ${plural(pwd.retiring, 'affected user', 'affected users')} first, in guided waves with device guidance.`], ['Govern non-user accounts', 'Service and shared accounts move under policy.'], ['Confirm readiness early', 'A final sweep before enforcement. No blocked sign-ins.']]
    const sx = X0 + lw + 0.5, sw = CW - lw - 0.5
    steps.forEach(([head, body], i) => {
      const y = TOP + i * 1.08
      chip(s, String(i + 1), sx, y + 0.05, 0.5, 0.5, C.text2, 16, `Step ${i + 1} number`)
      text(s, [{ text: head, options: { fontSize: 17, bold: true, color: C.text2, breakLine: true } }, { text: body, options: { fontSize: 13, color: C.text1, paraSpaceBefore: 2 } }], { x: sx + 0.7, y, w: sw - 0.7, h: 0.85, objectName: `Step ${i + 1}` })
    })
    card(s, X0, BOTTOM - 0.7, CW, 0.7, 'Outcome strip')
    text(s, [{ text: 'OUTCOME   ', options: { bold: true, color: C.text2, charSpacing: 1.5, fontSize: 11 } }, { text: `${pwd.deadline} arrives as a non-event: no blocked sign-ins, and phishing-resistant sign-in as the default.`, options: { color: C.text1, fontSize: 13 } }], { x: X0 + 0.25, y: BOTTOM - 0.7, w: CW - 0.5, h: 0.7, valign: 'middle', objectName: 'Outcome' })
    s.addNotes(notesOf([`${plural(pwd.retiring, 'user', 'users')} signed in with text message or voice over the last 30 days. Microsoft retires these methods on ${pwd.deadline}.`, pwd.authenticator ? `${plural(pwd.authenticator, 'user already uses', 'users already use')} Microsoft Authenticator, where a passkey can be issued.` : '', 'The plan enables passkeys under change control, registers affected users in guided waves, governs service and shared accounts, and confirms readiness with a final sweep before enforcement.']))
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
      text(s, [{ text: String(i + 1).padStart(2, '0'), options: { fontSize: 14, bold: true, color: C.accent1, breakLine: true } }, { text: a.title, options: { fontSize: 18, bold: true, color: C.background1, breakLine: true, paraSpaceBefore: 4 } }, { text: a.body, options: { fontSize: 13, color: C.background2, paraSpaceBefore: 4 } }], { x: x + 0.3, y: y + 0.2, w: cw - 0.6, h: ch - 0.3, objectName: `Ask ${i + 1}` })
    })
  } else {
    s.addShape(pres.shapes.RECTANGLE, { x: 0.7, y: 2.55, w: 9.7, h: 1.3, fill: { color: HEX.dk2, transparency: 12 }, line: { color: HEX.accent5, width: 0.75 }, objectName: 'No asks card' })
    text(s, 'Nothing needs approval or access from your team before the next review. The roadmap proceeds as sequenced.', { x: 1.0, y: 2.55, w: 9.1, h: 1.3, fontSize: 16, color: C.background1, valign: 'middle', objectName: 'No asks' })
  }
  text(s, 'At the next review we recollect the evidence and verify each outcome.', { x: 0.7, y: 6.82, w: 9.7, h: 0.35, fontSize: 13, color: C.background2, objectName: 'Next review' })
  s.addNotes(notesOf(['Close on the decisions. Each one unblocks a roadmap item, or lets us grade a control we cannot see today.', st.asks.map(a => `${a.title}. ${a.body}`)]))

  // Appendix: the control register, two pillars per slide, and on A3 how we grade.
  if (balanced) {
    pres.addSection({ title: 'Appendix' })
    const legend = 'E enforced, 90% or more · P partial, 50 to 89% · N not yet enforced · – not gathered'
    const VALUE_W = 1.55
    const registerSize = (regs, w) => {
      const labelW = w - 0.55 - VALUE_W
      const fits = size => regs.every(reg => {
        const tiers = [reg.foundational, reg.defense].filter(r => r.length)
        const need = tiers.reduce((n, rows) => n + rows.reduce((k, c) => k + (Math.min(2, lines(c.label, labelW, size)) + (c.detail ? lines(c.detail, labelW, size - 1) : 0)) * (size === 12 ? 0.215 : 0.2) + 0.08, 0), 0)
        return need <= 7.2 - TOP - 0.45 - tiers.length * 0.52
      })
      return fits(12) ? 12 : 11
    }
    const pillarColumn = (sl, reg, x, w, size) => {
      text(sl, reg.group, { x, y: TOP - 0.05, w: w * 0.62, h: 0.4, fontSize: 18, bold: true, color: C.text2, objectName: `${reg.group} register heading` })
      text(sl, reg.summary, { x: x + w * 0.5, y: TOP - 0.05, w: w * 0.5, h: 0.4, fontSize: 11, color: C.accent6, align: 'right', valign: 'middle', objectName: `${reg.group} register summary` })
      const tiers = [['foundational', 'Foundational', reg.foundational], ['defense', 'Defense in depth', reg.defense]].filter(([, , rows]) => rows.length)
      const labelW = w - 0.55 - VALUE_W
      const lineH = size === 12 ? 0.215 : 0.2
      let y = TOP + 0.45
      tiers.forEach(([key, label, rows]) => {
        const measured = rows.filter(c => c.mark)
        text(sl, label.toUpperCase(), { x, y, w: w * 0.7, h: 0.3, fontSize: 11, bold: true, color: C.accent2, charSpacing: 1.5, objectName: `${reg.group} ${key} label` })
        text(sl, measured.length ? `${measured.filter(c => c.mark === 'E').length} of ${measured.length}` : '', { x: x + w * 0.6, y, w: w * 0.4, h: 0.3, fontSize: 11, bold: true, color: C.accent2, align: 'right', objectName: `${reg.group} ${key} count` })
        rule(sl, x, y + 0.33, w, C.text2, 1, `${reg.group} ${key} rule`)
        y += 0.42
        rows.forEach(c => {
          // A control with a detail line (the ratio behind a Mostly enforced policy, or the resource types a
          // partially covered control is missing) carries it under the label.
          const h = (Math.min(2, lines(c.label, labelW, size)) + (c.detail ? lines(c.detail, labelW, size - 1) : 0)) * lineH + 0.07
          markChip(sl, c.chip, x, y + (h - 0.26) / 2, 0.36, 0.26, size, `${c.label} chip`)
          text(sl, c.detail ? [{ text: c.label, options: { fontSize: size, color: C.text1, breakLine: true } }, { text: c.detail, options: { fontSize: size - 1, color: C.accent6 } }] : c.label, { x: x + 0.48, y, w: labelW, h, fontSize: size, color: C.text1, valign: 'middle', objectName: `${c.label} register label` })
          text(sl, c.valueText, { x: x + w - VALUE_W, y, w: VALUE_W, h, fontSize: size, bold: !!c.mark, color: c.mark ? C.text2 : C.accent6, align: 'right', valign: 'middle', objectName: `${c.label} register value` })
          rule(sl, x, y + h + 0.005, w, HEX.track, 0.5, `${c.label} register rule`)
          y += h + 0.01
        })
        y += 0.1
      })
    }
    const regNotes = regs => notesOf(['Reference.', regs.map(r => [...r.foundational, ...r.defense].map(c => `${c.label}: ${c.valueText}. ${c.note}`))])
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
    const grade = [['Outcomes', 'Did the program hold? Alerts, confirmed threats, impact.'], ['Control effectiveness', 'What is actually enforced, graded E, P or N.'], ['Hardening next', 'Scoped and sequenced on the roadmap.'], ['Vendor benchmark, as context', bench || 'Microsoft scores are read as context, never as the objective.']]
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
      ['Alerts', m.ticketed ? 'Sentinel records that opened a ticket with the managed security service. Informational severity is excluded.' : 'Sentinel records triaged by the managed security service.'],
      ['Detections', 'Records from Sentinel, Defender for Cloud and the Defender services correlated into those alerts.'],
      ['Device measures', 'Azure virtual machines, including Azure Arc-enabled servers. Workstations and network appliances stay out.'],
      ['Status marks', 'Read at collection. A control below E is a gap against the baseline, not a change since the last review.']
    ]
    eyebrow(s, 'What the readings cover', X0, TOP - 0.05, half, C.text2, 'Scope')
    rule(s, X0, TOP + 0.3, half, C.text2, 1, 'Scope rule')
    let fy = TOP + 0.42
    facts.forEach(([k, v], i) => {
      const h = Math.max(0.28, lines(v, half - 2.4, 11) * 0.185 + 0.1)
      text(s, k, { x: X0, y: fy, w: 2.3, h, fontSize: 11, bold: true, color: C.text2, objectName: `Scope ${i + 1} label` })
      text(s, v, { x: X0 + 2.4, y: fy, w: half - 2.4, h, fontSize: 11, color: C.text1, objectName: `Scope ${i + 1} value` })
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
    // dropped: a partial collection can leave dozens of controls ungraded.
    const entryH = c => Math.min(2, lines(c.label, half - 0.5, 11)) * 0.185 + 0.26
    const fillColumn = (sl, x, from, prefix) => {
      let y = TOP + 0.42, i = from
      while (i < notGraded.length) {
        const c = notGraded[i], h = entryH(c)
        if (y + h > BOTTOM) break
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
    const scoreCard = (x, eye, score, body, name) => {
      card(s, x, TOP, cw2, ch2, `${name} card`)
      text(s, eye, { x: x + 0.3, y: TOP + 0.2, w: cw2 - 0.6, h: 0.3, fontSize: 11, bold: true, color: C.accent2, charSpacing: 1.5, objectName: `${name} eyebrow` })
      if (score !== null) {
        s.addChart(pres.charts.DOUGHNUT, [{ name, labels: ['Score', 'Remaining'], values: [score, Math.max(0, 100 - score)] }], { x: x + 0.25, y: TOP + 0.55, w: 2.25, h: 2.25, holeSize: 72, chartColors: [HEX.accent2, HEX.track], showLegend: false, showValue: false, showPercent: false, showLabel: false, showTitle: false, objectName: `${name} chart` })
        text(s, pctText(score), { x: x + 0.25, y: TOP + 1.37, w: 2.25, h: 0.6, fontSize: 22, bold: true, color: C.text2, align: 'center', valign: 'middle', objectName: `${name} value` })
      }
      text(s, body, { x: x + (score !== null ? 2.8 : 0.3), y: TOP + 0.65, w: cw2 - (score !== null ? 3.1 : 0.6), h: ch2 - 0.85, fontSize: 13, color: C.text1, valign: 'middle', objectName: `${name} text` })
    }
    const cs = m.cloudScore
    scoreCard(X0, 'DEFENDER FOR CLOUD · AZURE ESTATE', cs ? cs.value : null, cs ? [{ text: pctText(cs.value), options: { fontSize: 20, bold: true, color: C.text2, breakLine: true } }, { text: `${cs.note}${m.posture.assessed !== null ? ` Measured across ${fmt(m.posture.assessed)} assessed resources.` : ''}`, options: { breakLine: true, paraSpaceBefore: 4 } }, { text: cs.delta && cs.delta.points > 0 ? `Up ${fmt(cs.delta.points)} points since ${cs.delta.since}` : 'Reported as current state.', options: { color: cs.delta && cs.delta.points > 0 ? C.accent3 : C.accent6, paraSpaceBefore: 6 } }] : 'Reading completed in the review.', 'Defender for Cloud')
    const tsc = m.tenantScore
    scoreCard(X0 + cw2 + 0.3, 'MICROSOFT SECURE SCORE · MICROSOFT 365', tsc ? tsc.value : null, tsc ? [{ text: pctText(tsc.value), options: { fontSize: 20, bold: true, color: C.text2, breakLine: true } }, { text: tsc.note, options: { breakLine: !!tsc.delta, paraSpaceBefore: 4 } }, ...(tsc.delta ? [{ text: `Up ${fmt(tsc.delta.points)} points since ${tsc.delta.since}`, options: { color: C.accent3, paraSpaceBefore: 6 } }] : [])] : [{ text: 'Added from the portal reading', options: { fontSize: 18, bold: true, color: C.text2, breakLine: true } }, { text: 'The tenant score is read in the Defender portal and added through the review context so both estates are presented together.', options: { paraSpaceBefore: 6 } }], 'Secure Score')
    const inv = [[fmt(m.posture.estate), 'Azure resources in the estate', m.excluded ? `Managed resource groups matching ${m.excluded} are excluded.` : 'No managed resource group exclusion was configured.'], [fmt(m.posture.assessed), 'Resources assessed by Defender for Cloud', 'Distinct resources in assessment records at collection.'], m.posture.rules ? [fmt(m.posture.rules.enabled), 'Analytics rules active in Sentinel', `Of ${fmt(m.posture.rules.total)} rules across ${plural(m.workspaces.length, 'workspace', 'workspaces')}.`] : [fmt(m.posture.telemetryTables), 'Telemetry tables collected', 'Distinct data types reaching the workspaces.']]
    const iw = (CW - 0.6) / 3, iy = TOP + ch2 + 0.3
    inv.forEach(([v, l, sub], i) => stat(s, X0 + i * (iw + 0.3), iy, iw, BOTTOM - iy, v, l, sub, `Inventory ${i + 1}`))
    s.addNotes(notesOf(['Microsoft calculates both scores. We report them as benchmark and context, and we do not manage the environment to them.', `Tenant-wide sign-in readings use ${m.tenantWorkspace}. Alert metrics come from one combined query across the workspaces, and workspace medians and distinct counts are never added together.`, `Sentinel workspaces: ${m.workspaces.map(w => `${w.Name}, ${fmt(w.RetentionDays)} days retention`).join('. ')}.`]))

    s = content('Appendix', 'Where the next points are', 'Appendix A6 · Microsoft score controls ranked by the points still available')
    const sc = m.posture.scoreControls.slice(0, 8), leftW = 7.3
    if (sc.length) s.addChart(pres.charts.BAR, [{ name: 'Score control', labels: sc.map(c => `${c.label} (${fmt(c.remaining)} ${c.remaining === 1 ? 'pt' : 'pts'})`), values: sc.map(c => c.pct) }], {
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
    s.addNotes(notesOf(['Microsoft score controls pay out all or nothing, so remediation can land with no visible movement until a control completes.', st.headroom]))
  }

  console.log(await writeDeck(pres, path.resolve(outFile)))
}

main().catch(e => { console.error(e.message || e); process.exit(1) })
