/* PowerPoint edition of the controls standard (The Controls That Matter). Informational: it outlines
   the controls for executives and closes with an invitation for feedback, it does not ask for sign-off.
   The control list, tiers and measure text come from report-model.js run on an empty pack in standards
   mode, the same source as the HTML edition, so the two never drift.

   Usage: node report/build-controls-deck.cjs [output.pptx]
   Default output: docs/The Controls That Matter.pptx. Needs pptxgenjs (npm install pptxgenjs). */
'use strict'
const path = require('node:path')
const fs = require('node:fs')
const { createDeck, writeDeck, lines, THEME, X0, CW } = require('./deck-common.cjs')

const root = path.resolve(__dirname, '..')
const out = path.resolve(process.argv[2] || path.join(root, 'docs', 'The Controls That Matter.pptx'))
const info = JSON.parse(fs.readFileSync(path.join(__dirname, 'controls-standard.json'), 'utf8'))
const { build, clean } = require('./report-model.js')
const m = build({ parameters: { ClientName: 'MXDR controls standard' }, manifest: [], results: {}, standard: true })

const GROUPS = ['Identity and access', 'Endpoint and workload', 'Network and boundary', 'Data protection', 'Detection and response']
const TIERS = [
  { key: 'foundational', label: 'Foundational', letter: 'F', line: 'Configured at build and held at E at every review' },
  { key: 'defense', label: 'Defense in depth', letter: 'D', line: 'Layered on afterward and sequenced with each client on the roadmap' }
]
const inTier = (group, tier) => m.controls.filter(c => c.group === group && c.tier === tier)
const total = tier => m.controls.filter(c => c.tier === tier).length
const title = clean(info.Title) || 'The controls that matter'
const version = clean(info.Version)

async function main() {
  const { pres, C, card, chip, text } = createDeck({ title })

  // 1. Title
  pres.addSection({ title: 'Overview' })
  let s = pres.addSlide({ masterName: 'Atmosera Title', sectionTitle: 'Overview' })
  s.addText('MANAGED SECURITY SERVICES · SECURITY CONTROLS STANDARD', { placeholder: 'eyebrow' })
  s.addText(title.charAt(0).toUpperCase() + title.slice(1), { placeholder: 'title' })
  s.addText('MXDR security controls standard', { placeholder: 'subtitle' })
  s.addText('The controls every managed environment is held to, and how each one is measured.', { placeholder: 'caption' })
  s.addText(`${version ? `Version ${version} · ` : ''}${total('foundational')} foundational and ${total('defense')} defense in depth controls across five pillars`, { placeholder: 'meta' })
  s.addNotes('This deck outlines the controls Atmosera holds every managed environment to. It is informational. The controls are being put in place, and feedback on any control, its tier or how it is measured is welcome at the end.')

  // 2. Two tiers
  s = pres.addSlide({ masterName: 'Atmosera Content', sectionTitle: 'Overview' })
  s.addText('Two tiers of controls', { placeholder: 'title' })
  s.addText('Foundational controls are built in. Defense in depth is layered on with each client.', { placeholder: 'subtitle' })
  const tierCards = [
    { tier: TIERS[0], fill: C.accent2, body: 'Configured when the environment is built and expected to stay enforced at every review. One that reads below E is treated as drift and carries a fix date.', head: 'Foundational when all three hold', items: ['Other controls in the pillar depend on it.', 'It applies to every client in scope of the service.', 'Atmosera can deliver it inside the build window.'] },
    { tier: TIERS[1], fill: C.text2, body: 'The additional safeguards layered on afterward. Each waits on something the client approves, schedules or licenses, and they are sequenced on the roadmap.', head: 'Defense in depth when any one is true', items: ['It needs application or dependency testing only the client can perform.', 'It needs a maintenance window, a reboot or a redeployment.', 'It changes network or directory architecture.', 'It needs licensing or recurring cost beyond the service agreement.', 'It depends on tuning against the environment\'s own operating history.'] }
  ]
  const tw = (CW - 0.4) / 2
  tierCards.forEach((t, i) => {
    const x = X0 + i * (tw + 0.4), y = 1.75, h = 5.3
    card(s, x, y, tw, h, `${t.tier.label} card`)
    chip(s, t.tier.letter, x + 0.3, y + 0.3, 0.55, 0.5, t.fill, 20, `${t.tier.label} chip`)
    text(s, t.tier.label, { x: x + 1.05, y: y + 0.3, w: tw - 1.35, h: 0.5, fontSize: 24, bold: true, color: C.text2, valign: 'middle', objectName: `${t.tier.label} heading` })
    text(s, t.body, { x: x + 0.3, y: y + 1.0, w: tw - 0.6, h: 1.05, fontSize: 15, color: C.text1, objectName: `${t.tier.label} definition` })
    text(s, t.head, { x: x + 0.3, y: y + 2.15, w: tw - 0.6, h: 0.4, fontSize: 15, bold: true, color: t.fill, objectName: `${t.tier.label} criteria heading` })
    text(s, t.items.map((it, n) => ({ text: it, options: { bullet: true, breakLine: n < t.items.length - 1, paraSpaceAfter: 6 } })), { x: x + 0.3, y: y + 2.6, w: tw - 0.6, h: h - 2.85, fontSize: 14, color: C.text1, objectName: `${t.tier.label} criteria` })
  })
  s.addNotes('Every control sits in one of two tiers. Foundational controls go in during the build and should read E at every review. Defense in depth controls each need something from the client, such as testing, a maintenance window or licensing, so they are sequenced on the roadmap.')

  // 3. Grading
  s = pres.addSlide({ masterName: 'Atmosera Content', sectionTitle: 'Overview' })
  s.addText('How each control is graded', { placeholder: 'title' })
  s.addText('Every control carries one status at each review', { placeholder: 'subtitle' })
  const marks = [
    { mark: 'E', fill: C.accent3, value: '90% or more', label: 'Enforced on in-scope resources' },
    { mark: 'P', fill: C.accent2, value: '50 to 89%', label: 'Partial, enforced on some resources' },
    { mark: 'N', fill: C.accent4, value: 'Under 50%', label: 'Not yet enforced' }
  ]
  const mw = (CW - 0.6) / 3
  marks.forEach((k, i) => {
    const x = X0 + i * (mw + 0.3), y = 1.75
    card(s, x, y, mw, 2.7, `${k.mark} card`)
    chip(s, k.mark, x + 0.35, y + 0.35, 0.85, 0.85, k.fill, 36, `${k.mark} mark`)
    text(s, k.value, { x: x + 0.35, y: y + 1.35, w: mw - 0.7, h: 0.6, fontSize: 30, bold: true, color: C.text2, objectName: `${k.mark} threshold` })
    text(s, k.label, { x: x + 0.35, y: y + 1.95, w: mw - 0.7, h: 0.4, fontSize: 15, color: C.accent6, objectName: `${k.mark} label` })
  })
  const notesW = (CW - 0.3) / 2
  ;[
    { head: 'In force or Not in force', body: 'A control read from a policy or tenant setting rather than a count, such as a Conditional Access policy, reads In force or Not in force.', name: 'In force note' },
    { head: 'N/A', body: 'A control with no activity or configuration to judge it by reads N/A and is left out of every count.', name: 'N/A note' }
  ].forEach((n, i) => {
    const x = X0 + i * (notesW + 0.3), y = 4.75
    card(s, x, y, notesW, 1.95, `${n.name} card`)
    text(s, [{ text: n.head, options: { fontSize: 20, bold: true, color: C.text2, breakLine: true } }, { text: n.body, options: { fontSize: 15, color: C.text1, paraSpaceBefore: 8 } }], { x: x + 0.35, y: y + 0.3, w: notesW - 0.7, h: 1.4, objectName: n.name })
  })
  s.addNotes('Most controls are a share of in-scope resources, graded E at 90 percent or more, P from 50 to 89 and N below 50. Controls read from a policy or setting read In force or Not in force. N/A means there was nothing to judge, and it never moves a count.')

  // 4. Controls by pillar
  s = pres.addSlide({ masterName: 'Atmosera Content', sectionTitle: 'Overview' })
  s.addText('Controls by pillar', { placeholder: 'title' })
  s.addText(`${m.controls.length} controls across five pillars`, { placeholder: 'subtitle' })
  s.addChart(pres.charts.BAR, TIERS.map(t => ({ name: t.label, labels: GROUPS, values: GROUPS.map(g => inTier(g, t.key).length) })), {
    x: X0, y: 1.7, w: 8.4, h: 5.4, barDir: 'bar', barGrouping: 'stacked', barGapWidthPct: 45,
    chartColors: [THEME.colors.accent2, THEME.colors.dk2],
    showValue: true, dataLabelPosition: 'ctr', dataLabelColor: 'FFFFFF', dataLabelFontSize: 14, dataLabelFontBold: true, dataLabelFontFace: '+mn-lt',
    catAxisOrientation: 'maxMin', catAxisLabelColor: THEME.colors.dk1, catAxisLabelFontSize: 14, catAxisLabelFontFace: '+mn-lt', catAxisLineShow: false,
    valAxisHidden: true, valGridLine: { style: 'none' }, catGridLine: { style: 'none' },
    showLegend: true, legendPos: 'b', legendFontSize: 14, legendFontFace: '+mn-lt', legendColor: THEME.colors.dk1,
    showTitle: false, objectName: 'Controls by pillar chart'
  })
  ;[
    { value: String(m.controls.length), label: 'controls in the standard', color: C.text2 },
    { value: String(total('foundational')), label: 'foundational', color: C.accent2 },
    { value: String(total('defense')), label: 'defense in depth', color: C.text2 }
  ].forEach((st, i) => {
    const y = 1.85 + i * 1.75
    card(s, 9.4, y, CW + X0 - 9.4, 1.5, `${st.label} card`)
    text(s, [{ text: st.value, options: { fontSize: 48, bold: true, color: st.color, breakLine: true } }, { text: st.label, options: { fontSize: 15, color: C.accent6 } }], { x: 9.75, y: y + 0.15, w: CW + X0 - 10.1, h: 1.25, objectName: `${st.label} stat` })
  })
  s.addNotes('Each pillar holds a mix of foundational and defense in depth controls. The pages that follow list every control in each pillar, one tier per page, with how it is measured.')

  // 5. One page per pillar and tier, three cards across.
  GROUPS.forEach(group => {
    pres.addSection({ title: group })
    TIERS.forEach(t => {
      const items = inTier(group, t.key)
      if (!items.length) return
      const sl = pres.addSlide({ masterName: 'Atmosera Content', sectionTitle: group })
      sl.addText(group, { placeholder: 'title' })
      sl.addText(`${t.label} · ${items.length} controls · ${t.line}`, { placeholder: 'subtitle' })
      const cols = 3, rows = Math.ceil(items.length / cols)
      const gap = rows > 2 ? 0.22 : 0.3, cw = (CW - (cols - 1) * 0.3) / cols
      const top = rows > 2 ? 1.65 : 1.75, avail = 7.15 - top
      // Cards are as tall as the fullest one on the page needs, within the space available.
      const textW = cw - 1.08
      const need = Math.max(...items.map(c => 0.2 + lines(c.label, textW, 14, true) * 0.245 + 0.08 + lines(c.note, textW, 12) * 0.2 + 0.22))
      const ch = Math.min((avail - (rows - 1) * gap) / rows, Math.max(1.35, need))
      const fill = t.key === 'foundational' ? C.accent2 : C.text2
      items.forEach((c, i) => {
        const x = X0 + (i % cols) * (cw + 0.3), y = top + Math.floor(i / cols) * (ch + gap)
        const tag = `${t.letter}${i + 1}`
        card(sl, x, y, cw, ch, `${tag} card`)
        chip(sl, tag, x + 0.2, y + 0.22, 0.55, 0.36, fill, 13, `${tag} tag`)
        text(sl, [{ text: c.label, options: { fontSize: 14, bold: true, color: C.text2, breakLine: true } }, { text: c.note, options: { fontSize: 12, color: C.accent6, paraSpaceBefore: 5 } }], { x: x + 0.9, y: y + 0.2, w: textW, h: ch - 0.32, objectName: `${tag} ${c.label}` })
      })
      sl.addNotes(`${group}, ${t.label.toLowerCase()} controls. ${t.key === 'foundational' ? 'These are configured when the environment is built and are expected at E at every review.' : 'Each of these waits on something the client approves, schedules or licenses, and is sequenced on the roadmap.'} ${items.map(c => `${c.label}: ${c.note}`).join(' ')}`)
    })
  })

  // 6. Feedback
  pres.addSection({ title: 'Feedback' })
  s = pres.addSlide({ masterName: 'Atmosera Closing', sectionTitle: 'Feedback' })
  s.addText('Feedback welcome', { placeholder: 'title' })
  s.addText('Feedback on any control, its tier or how it is measured is welcome and is weighed for the next version of this standard.', { placeholder: 'body' })
  s.addNotes('Close by inviting feedback on the controls, their tiers and their measures. Feedback is considered for the next version of the standard.')

  console.log(await writeDeck(pres, out))
}

main().catch(e => { console.error(e.message || e); process.exit(1) })
