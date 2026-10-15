// PowerPoint edition of the report (report/build-report-deck.cjs): pages follow the depth, the
// copy rules hold, and speaker notes never carry the presenter notes.
const { test } = require('node:test')
const assert = require('node:assert/strict')
const fs = require('node:fs')
const os = require('node:os')
const path = require('node:path')
const { execFileSync } = require('node:child_process')
const { build } = require('../report/report-model.js')
const { JSZip } = require('../report/deck-common.cjs')

function pack(depth, threats = []) {
  const p = {
    depth,
    parameters: { ClientName: 'Example', WindowStart: '2025-11-01', WindowEnd: '2026-09-30', RecentStart: '2026-07-01', PostureReadDate: '2026-10-08', DefenderApi: 'available', Subscriptions: ['s1'], Workspaces: [{ Name: 'w1', CustomerId: 'w1', RetentionDays: 365 }], AlertScope: 'Ticketed incidents only' },
    manifest: [], results: {}, context: null
  }
  const put = (id, rows) => { p.manifest.push({ ResultId: id, Status: 'OK', Rows: rows.length, ReadTimeUtc: '2026-10-08T10:00:00Z' }); p.results[id] = rows }
  put('P0.1-XDRDUP', [{ XdrIncidents: 20, InMultipleWorkspaces: 0 }])
  put('OUT.1', [{ Raised: 100, Closed: 80, Open: 20, TruePositive: 3, ClosedUnclassified: 5 }])
  put('OUT.2', [{ Scope: 'All', Incidents: 80, AutoClosed: 10, MedianCloseMin: 22, P90CloseMin: 60 }, { Scope: 'High', Incidents: 30, AutoClosed: 0, MedianCloseMin: 25, P90CloseMin: 45 }])
  put('OUT.3', [{ Month: '2026-08-01', Total: 40, High: 4, Medium: 10, Low: 26, Informational: 0 }, { Month: '2026-09-01', Total: 60, High: 9, Medium: 20, Low: 31, Informational: 0 }])
  put('OUT.5', [{ ProductName: 'Azure Sentinel', AlertSeverity: 'High', Alerts: 40 }])
  put('IA.1', [{ UserType: 'Member', UsersSignedIn: 100, UsersChallenged: 90 }])
  put('IA.2', [{ Bucket: 'SMS or voice', DistinctUsers: 7, SignIns: 40 }])
  put('DP.2', [{ Vaults: 6, SoftDelete: 6, PurgeProtection: 0, RbacAuth: 3 }]) // foundational drift, a presenter note
  put('POS.1', [{ Current: 20, Max: 40, Subscriptions: 1, Percent: 50 }])
  if (threats.length) put('OUT.4', threats)
  return p
}
function deck(depth, threats) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ebr-deck-'))
  const data = pack(depth, threats), dataFile = path.join(dir, 'data.json'), out = path.join(dir, 'deck.pptx')
  fs.writeFileSync(dataFile, JSON.stringify(data))
  execFileSync(process.execPath, [path.join(__dirname, '..', 'report', 'build-report-deck.cjs'), dataFile, out])
  return { data, out }
}
// The stock control labels all fit one line of the scope appendix, so a wrapped entry needs a label past the wrap
// width. The builder is copied beside a model with one label lengthened, the way a future label change would reach
// this layout, and the copy is run.
const LONG_LABEL = 'Location-based sign-in access controls enforced through Conditional Access'
function wrappedDeck(depth) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ebr-deck-')), copy = path.join(dir, 'report')
  fs.cpSync(path.join(__dirname, '..', 'report'), copy, { recursive: true })
  const model = path.join(copy, 'report-model.js'), source = fs.readFileSync(model, 'utf8')
  assert.equal(source.split(`'${LONG_LABEL}'`).length, 2, 'the lengthened label is in the model once')
  fs.writeFileSync(model, source.replace(`'${LONG_LABEL}'`, `'${LONG_LABEL} policies'`))
  const data = pack(depth), dataFile = path.join(dir, 'data.json'), out = path.join(dir, 'deck.pptx')
  fs.writeFileSync(dataFile, JSON.stringify(data))
  const NODE_PATH = [path.join(__dirname, '..', 'node_modules'), process.env.NODE_PATH].filter(Boolean).join(path.delimiter)
  execFileSync(process.execPath, [path.join(copy, 'build-report-deck.cjs'), dataFile, out], { env: { ...process.env, NODE_PATH } })
  return { data, out, label: `${LONG_LABEL} policies` }
}
async function read(file) {
  const zip = await JSZip.loadAsync(fs.readFileSync(file))
  const texts = async re => Promise.all(Object.keys(zip.files).filter(n => re.test(n)).sort().map(async n => (await zip.file(n).async('string')).match(/<a:t>[^<]*<\/a:t>/g)?.map(t => t.slice(5, -6)).join(' ') || ''))
  return { slides: await texts(/^ppt\/slides\/slide\d+\.xml$/), notes: await texts(/^ppt\/notesSlides\/notesSlide\d+\.xml$/) }
}

test('the deck follows the report depth', async () => {
  const counts = {}
  for (const depth of ['brief', 'balanced', 'detailed']) counts[depth] = (await read(deck(depth).out)).slides.length
  assert.ok(counts.brief < counts.balanced && counts.balanced < counts.detailed, JSON.stringify(counts))
  const brief = await read(deck('brief').out)
  assert.ok(!brief.slides.some(s => /Security operations|Control posture|Control register/.test(s)), 'operations, posture and the register are balanced-only')
  for (const title of ['Executive summary', 'Hardening roadmap', 'Decisions needed']) assert.ok(brief.slides.some(s => s.includes(title)), title)
  const balancedDeck = await read(deck('balanced').out)
  for (const title of ['Security operations', 'Control posture', 'Control register: identity and endpoint', 'Control register: network and data', 'Control register: detection, and how we grade']) assert.ok(balancedDeck.slides.some(s => s.includes(title)), title)
  const detailed = await read(deck('detailed').out)
  assert.ok(detailed.slides.some(s => /Tenant and cloud security posture/.test(s)), 'posture is detailed-only')
})
const examples = [
  { Threat: 'Log4j vulnerability exploit aka Log4Shell IP IOC', Severity: 'High', Tactics: 'CommandAndControl', Created: '2026-08-18', ExfilOrImpactTactic: false },
  { Threat: 'Password spray attack against Microsoft Entra ID application', Severity: 'Medium', Tactics: 'CredentialAccess', Created: '2026-07-28', ExfilOrImpactTactic: false }
]
// Shape positions in the slide XML, in EMU. The content area ends at BOTTOM, 7.0 in.
const EMU = 914400, BOTTOM_EMU = 7.0 * EMU
// The scope appendix slides: every not-graded entry box, chip and rule with its position, the continuation marker
// when the slide has one, and the slide text. The bottom 0.35 in of every column is kept for the marker.
const BAND_EMU = BOTTOM_EMU - Math.round(0.35 * EMU)
async function scopeSlides(out) {
  const zip = await JSZip.loadAsync(fs.readFileSync(out))
  const xmls = (await Promise.all(Object.keys(zip.files).filter(n => /^ppt\/slides\/slide\d+\.xml$/.test(n)).map(n => zip.file(n).async('string')))).filter(x => x.includes('name="Ungathered'))
  return xmls.map(xml => {
    const shapes = [...xml.matchAll(/<p:cNvPr id="\d+" name="([^"]*)"(?:(?!<p:cNvPr)[\s\S])*?<a:off x="\d+" y="(\d+)"\/><a:ext cx="\d+" cy="(\d+)"\/>/g)].map(s => ({ name: s[1], y: Number(s[2]), h: Number(s[3]), bottom: Number(s[2]) + Number(s[3]) }))
    const entries = shapes.filter(s => /^Ungathered(?: page \d+ (?:left|right))? \d+(?: chip(?: text)?| rule)?$/.test(s.name))
    return { entries, boxes: entries.filter(s => /\d$/.test(s.name)), marker: shapes.find(s => / continued$/.test(s.name)), text: (xml.match(/<a:t>[^<]*<\/a:t>/g) || []).map(t => t.slice(5, -6)).join(' ').replace(/\u00A0/g, ' ') }
  })
}
// No entry reaches into the band, the marker sits below every entry on a slide that continues, and every ungraded
// control has one entry box.
function assertClearOfMarker(slides, count) {
  for (const { entries, marker } of slides) {
    assert.ok(entries.length, 'the slide has not-graded entries')
    for (const s of entries) assert.ok(s.bottom <= BAND_EMU + 1, `"${s.name}" ends at ${(s.bottom / EMU).toFixed(3)} in, inside the bottom band`)
    if (marker) {
      assert.ok(marker.bottom <= BOTTOM_EMU + 1, 'the marker ends above BOTTOM')
      for (const s of entries) assert.ok(s.bottom <= marker.y, `"${s.name}" runs under the continuation marker`)
    }
  }
  assert.equal(slides.reduce((n, s) => n + s.boxes.length, 0), count, 'one entry box per ungraded control')
}
async function threatsSlide(out) {
  const zip = await JSZip.loadAsync(fs.readFileSync(out))
  const xmls = await Promise.all(Object.keys(zip.files).filter(n => /^ppt\/slides\/slide\d+\.xml$/.test(n)).map(n => zip.file(n).async('string')))
  const xml = xmls.find(x => x.includes('name="Confirmed threats caption"'))
  assert.ok(xml, 'the confirmed threats slide is there')
  const shape = name => {
    const match = xml.match(new RegExp(`name="${name}"[\\s\\S]*?<a:off x="(\\d+)" y="(\\d+)"/><a:ext cx="(\\d+)" cy="(\\d+)"/>`))
    assert.ok(match, `the slide has a "${name}" shape with a position`)
    return match.slice(1).map(Number)
  }
  const [, tableY] = shape('Confirmed threats table'), [, captionY, , captionH] = shape('Confirmed threats caption')
  const rows = [...xml.matchAll(/<a:tr h="(\d+)"[^>]*>([\s\S]*?)<\/a:tr>/g)]
  const text = (xml.match(/<a:t>[^<]*<\/a:t>/g) || []).map(t => t.slice(5, -6))
  return { xml, tableY, tableH: rows.reduce((n, r) => n + Number(r[1]), 0), captionY, captionH, body: rows.slice(1).map(r => r[2]), text }
}
test('slide text follows the copy rules and speaker notes never carry the presenter notes', async () => {
  const incident = { Threat: 'Multi-stage incident involving Initial access and Execution on one endpoint', Severity: 'High', Tactics: 'InitialAccess,Execution', Created: '2026-08-01', ExfilOrImpactTactic: false }
  const { data, out } = deck('detailed', [...examples, incident])
  const m = build(data)
  assert.ok(m.presenter.some(n => n.title === 'Foundational controls below E'), 'the fixture raises a presenter note')
  const { slides, notes } = await read(out)
  const all = slides.join(' ')
  assert.ok(all.includes('Multi-stage alert involving Initial access and Execution on one endpoint'), 'the incident title reads as an alert')
  assert.ok(!/;|→|←|object Object|\(null\)|\bincidents?\b/i.test(all.replace(/&[a-z]+;|&#\d+;/g, '')), all.match(/.{0,40}(;|object Object|\(null\)|incident).{0,40}/i)?.[0])
  assert.ok(!/\bNaN\b|\bundefined\b/.test(all), 'a missing value reached the slides')
  assert.ok(all.includes('Example'))
  const spoken = notes.join(' ')
  for (const n of [...m.presenter, ...m.review]) assert.ok(!spoken.includes(n.text), `speaker notes carry the presenter note "${n.title}"`)
  assert.ok(!/Foundational controls below E|foundational controls? reads? below E:|Prepared answers|Evidence review/.test(spoken))
  // The evidence holds the current reading only, so the deck never says a control was configured at build, drifted or regressed.
  assert.ok(!/\bat build\b|\bdrift|\bregress|\bsince the last review\b(?! )/i.test(all.replace(/not a change since the last review/g, '')), all.match(/.{0,50}(at build|drift|regress).{0,50}/i)?.[0])
  assert.ok(!/\bat build\b|\bdrift|\bregress/i.test(spoken), spoken.match(/.{0,50}(at build|drift|regress).{0,50}/i)?.[0])
})
test('the grounding slides appear at balanced depth and carry the pillar narratives, the priority workstreams and the scope', async () => {
  const { data, out } = deck('balanced', examples)
  const m = build(data)
  const { slides, notes } = await read(out)
  const pillars = slides.find(s => s.startsWith('Measured outcomes by pillar'))
  assert.ok(pillars, 'the pillar outcomes slide')
  for (const p of m.pillars) assert.ok(pillars.includes(p.name) && pillars.includes(p.headline), p.name)
  // Figures and dates are glued with non-breaking spaces on the slide, so the comparison reads them as spaces.
  const plain = s => s.replace(/\u00A0/g, ' ')
  const work = plain(slides.find(s => s.startsWith('Priority workstreams')) || '')
  assert.ok(work, 'the priority workstreams slide')
  for (const p of m.priorities.slice(0, 3)) assert.ok(work.includes(p.title) && work.includes(p.action) && work.includes(p.success), p.title)
  assert.ok(/EVIDENCE.*ACTION.*OUTCOME/.test(work))
  const scope = slides.find(s => s.startsWith('Scope and evidence'))
  assert.ok(scope && scope.includes('Appendix A4') && plain(scope).includes(m.period.label), 'the scope slide names the period')
  assert.ok(scope.includes('NOT GRADED IN THIS COLLECTION'))
  const brief = await read(deck('brief', examples).out)
  assert.ok(!brief.slides.some(s => /Measured outcomes by pillar|Priority workstreams|Scope and evidence/.test(s)), 'brief keeps the short deck')
  const detailed = await read(deck('detailed', examples).out)
  assert.ok(detailed.slides.some(s => /Appendix A5/.test(s)) && detailed.slides.some(s => /Appendix A6/.test(s)), 'the score slides follow the scope slide')
  assert.ok(notes.some(n => n.includes(m.pillars[0].narrative)), 'the full narrative is spoken')
})
test('the scope appendix lists every ungraded control, continuing onto further slides when one column is not enough', async () => {
  // The fixture pack leaves most controls ungathered, far more than one column holds.
  const { data, out } = deck('balanced')
  const m = build(data)
  const ungraded = m.controls.filter(c => c.measured === false)
  assert.ok(ungraded.length > 20, `fixture has ${ungraded.length} ungraded controls`)
  const { slides } = await read(out)
  const scope = slides.filter(s => /^Scope and evidence/.test(s))
  assert.ok(scope.length >= 2, 'the list continues onto a second slide')
  const all = scope.join(' ').replace(/\u00A0/g, ' ')
  for (const c of ungraded) assert.ok(all.includes(c.label), `${c.label} is listed`)
  assert.ok(/Continued on the next slide, \d+ more controls\./.test(all))
  assert.ok(!scope[scope.length - 1].includes('Continued on the next slide'), 'the last slide does not promise another')
  // With one-line entries the columns end at 6.575 in, clear of the marker at 6.70 in either way.
  const geometry = await scopeSlides(out)
  assert.equal(geometry.length, scope.length, 'every scope slide carries the not-graded column')
  assertClearOfMarker(geometry, ungraded.length)
})
test('a wrapped last entry moves on to the next column instead of running under the continuation marker', async () => {
  // One label lengthened past the wrap width makes a two-line entry. Filling to BOTTOM, a column of eight one-line
  // entries and that entry ended at 6.76 in, under the marker. The band stops the column first and the entry moves on.
  const { data, out, label } = wrappedDeck('balanced')
  const ungraded = build(data).controls.filter(c => c.measured === false)
  const slides = await scopeSlides(out)
  const home = slides.find(s => s.text.includes(label))
  assert.ok(home, 'the lengthened label is listed')
  assert.ok(home.boxes.some(b => b.h >= Math.round(0.6 * EMU)), 'the lengthened label gets a two-line entry box')
  assert.ok(home.marker, 'the two-line entry lands on a slide that continues, where the old fill ran it under the marker')
  assertClearOfMarker(slides, ungraded.length)
})
test('a register detail that wraps gets a row tall enough for every line', async () => {
  const p = pack('balanced')
  p.manifest.push({ ResultId: 'DR.2', Status: 'OK', Rows: 3, ReadTimeUtc: '2026-10-08T10:00:00Z' })
  p.results['DR.2'] = [{ Plan: 'AI', ResourceType: 'microsoft.cognitiveservices/accounts', Resources: 24, Covered: 0 }, { Plan: 'VirtualMachines', ResourceType: 'microsoft.compute/virtualmachines', Resources: 21, Covered: 19 }, { Plan: 'StorageAccounts', ResourceType: 'microsoft.storage/storageaccounts', Resources: 30, Covered: 29 }]
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ebr-deck-')), dataFile = path.join(dir, 'data.json'), out = path.join(dir, 'deck.pptx')
  fs.writeFileSync(dataFile, JSON.stringify(p))
  execFileSync(process.execPath, [path.join(__dirname, '..', 'report', 'build-report-deck.cjs'), dataFile, out])
  const zip = await JSZip.loadAsync(fs.readFileSync(out))
  const xml = (await Promise.all(Object.keys(zip.files).filter(n => /^ppt\/slides\/slide\d+\.xml$/.test(n)).map(n => zip.file(n).async('string')))).find(x => x.includes('register label') && x.includes('AI services'))
  assert.ok(xml, 'the detection register slide carries the detail')
  // Every register label box ends before the next rule under it starts.
  const boxes = [...xml.matchAll(/name="([^"]*) register label"[\s\S]*?<a:off x="\d+" y="(\d+)"\/><a:ext cx="\d+" cy="(\d+)"\/>/g)].map(m => ({ label: m[1], y: Number(m[2]), h: Number(m[3]) }))
  const rules = [...xml.matchAll(/name="([^"]*) register rule"[\s\S]*?<a:off x="\d+" y="(\d+)"\/>/g)].map(m => ({ label: m[1], y: Number(m[2]) }))
  const gap = boxes.find(b => /Cloud workload protection/.test(b.label)), rule = rules.find(r => /Cloud workload protection/.test(r.label))
  assert.ok(gap && rule, 'the workload protection row')
  assert.ok(gap.y + gap.h <= rule.y + 1, 'the box ends at its own rule')
  assert.ok(gap.h > 2 * 0.2 * 914400, 'the row holds the label and at least two detail lines')
})
test('a licensed control as the only foundational gap never reads as every foundational control enforced', async () => {
  const p = pack('balanced')
  p.results['DP.2'][0].PurgeProtection = 6 // no other foundational gap
  p.manifest.push({ ResultId: 'DR.11', Status: 'UNAVAILABLE', Rows: 0, ReadTimeUtc: '2026-10-08T10:00:00Z', AccessGap: false, NotOnboarded: true })
  p.manifest.push({ ResultId: 'NB.10', Status: 'OK', Rows: 1, ReadTimeUtc: '2026-10-08T10:00:00Z' })
  p.results['NB.10'] = [{ Scope: 'Azure VM', Devices: 3, Compliant: 0 }] // domain controllers in Azure, so the control applies
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ebr-deck-')), dataFile = path.join(dir, 'data.json'), out = path.join(dir, 'deck.pptx')
  fs.writeFileSync(dataFile, JSON.stringify(p))
  execFileSync(process.execPath, [path.join(__dirname, '..', 'report', 'build-report-deck.cjs'), dataFile, out])
  const { slides } = await read(out)
  const posture = slides.find(s => s.startsWith('Control posture'))
  assert.ok(posture, 'the posture slide')
  assert.ok(!/No foundational gaps|Every measured foundational control reads E/.test(posture), posture.match(/.{0,60}foundational control reads E.{0,20}/)?.[0])
  assert.ok(/needs licensing and sits in Later/.test(posture))
  assert.ok(/waiting on licensing/.test(posture))
})
test('chart workbooks carry valid table ranges so Keynote and Quick Look draw the charts', async () => {
  // pptxgenjs 4.0.1 writes ref="A1:D4'" into each chart's embedded table. Apple's importer then
  // drops the chart, so writeDeck repairs the range.
  const zip = await JSZip.loadAsync(fs.readFileSync(deck('detailed').out))
  const books = Object.keys(zip.files).filter(n => /^ppt\/embeddings\/.+\.xlsx$/.test(n))
  assert.ok(books.length >= 2, 'the operations slide has two charts')
  for (const name of books) {
    const book = await JSZip.loadAsync(await zip.file(name).async('nodebuffer'))
    for (const part of Object.keys(book.files).filter(n => /^xl\/tables\/.+\.xml$/.test(n))) {
      const ref = (await book.file(part).async('string')).match(/<table\b[^>]*\bref="([^"]*)"/)?.[1]
      assert.match(ref, /^[A-Z]+\d+:[A-Z]+\d+$/, `${name} ${part} has the range "${ref}"`)
    }
  }
})
test('confirmed threats get their own slide at balanced and detailed depth, only when there are examples', async () => {
  const isThreats = s => s.includes('Confirmed threats') && s.includes('Log4Shell')
  const has = async (depth, rows) => (await read(deck(depth, rows).out)).slides.some(isThreats)
  const { data, out } = deck('balanced', examples)
  const { slides, notes } = await read(out)
  const slide = slides.find(isThreats)
  assert.ok(slide, 'balanced has the slide')
  assert.equal(await has('detailed', examples), true)
  assert.equal(await has('brief', examples), false)
  const plain = (await read(deck('balanced').out)).slides
  assert.ok(!plain.some(s => /Attack stage/.test(s)), 'no examples, no slide')
  assert.ok(/Command and control/.test(slide) && /August\u00A02026/.test(slide) && /July\u00A02026/.test(slide), 'stage and month, with the year bound to the month')
  const m = build(data)
  for (const n of [...m.presenter, ...m.review]) assert.ok(!notes.join(' ').includes(n.text), `speaker notes carry "${n.title}"`)
})
test('the more line counts the alerts and groups past the five examples', async () => {
  const group = (name, severity, n) => Array.from({ length: n }, (_, i) => ({ Threat: `${name} detected`, Severity: severity, Tactics: 'Execution', Created: `2026-08-1${i}`, ExfilOrImpactTactic: false }))
  const five = ['Alpha', 'Bravo', 'Charlie', 'Delta', 'Echo'].flatMap(n => group(n, 'High', 1))
  const caption = async rows => (await threatsSlide(deck('balanced', rows).out)).text.find(t => t.endsWith('grouped by alert title.'))
  assert.equal(await caption([...five, ...group('Foxtrot', 'Low', 2), ...group('Golf', 'Low', 1)]), 'And 3 more confirmed alerts in 2 further groups. Confirmed as true positives by the SOC and closed, grouped by alert title.')
  assert.equal(await caption([...five, ...group('Foxtrot', 'Low', 1)]), 'And 1 more confirmed alert in 1 further group. Confirmed as true positives by the SOC and closed, grouped by alert title.')
  assert.equal(await caption(five), 'Confirmed as true positives by the SOC and closed, grouped by alert title.')
})
test('five long threat titles still end above the slide bottom, at 12 pt or cut with three dots', async () => {
  const subjects = ['Credential', 'Mailbox', 'Endpoint', 'Storage', 'Directory']
  const long = subjects.map((w, i) => ({ Threat: `${w} activity flagged as part of a multistage attack involving initial access, persistence, privilege escalation and lateral movement across several endpoints`, Severity: 'High', Tactics: 'InitialAccess,Persistence,PrivilegeEscalation', Created: `2026-0${i + 4}-10`, ExfilOrImpactTactic: false }))
  assert.ok(long.every(r => r.Threat.length >= 125))
  const { xml, tableY, tableH, captionY, captionH, body, text } = await threatsSlide(deck('balanced', long).out)
  assert.ok(tableY + tableH <= captionY, 'the caption sits below the table')
  assert.ok(captionY + captionH <= BOTTOM_EMU, `the caption ends at ${((captionY + captionH) / EMU).toFixed(2)} in, past BOTTOM`)
  for (const row of body) assert.deepEqual([...new Set(row.match(/<a:rPr\b[^>]*\bsz="(\d+)"/g).map(r => r.match(/sz="(\d+)"/)[1]))], ['1200'], 'body runs at 12 pt')
  // Whatever the room below the table holds (the outcome cards here, the handling strip too on a shorter table), every shape ends above the slide bottom.
  const bottoms = [...xml.matchAll(/<a:off x="\d+" y="(\d+)"\/><a:ext cx="\d+" cy="(\d+)"\/>/g)].map(m => Number(m[1]) + Number(m[2]))
  assert.ok(Math.max(...bottoms) <= BOTTOM_EMU + 1, `a shape ends at ${(Math.max(...bottoms) / EMU).toFixed(2)} in, past BOTTOM`)
  assert.ok(!text.join(' ').includes('…'), 'an ellipsis glyph reached the slide')
  for (const w of subjects) {
    const title = text.find(t => t.startsWith(`${w} activity`))
    assert.ok(title, `${w} row`)
    assert.ok(long.some(r => r.Threat === title) || /\w\.\.\.$/.test(title), `"${title}" is cut without three dots`)
  }
})
test('titles that are one long token still end above the slide bottom', async () => {
  const subjects = ['Credential', 'Mailbox', 'Endpoint', 'Storage', 'Directory']
  const tokens = subjects.map((w, i) => ({ Threat: `${w}_${'suspicious_activity_detected_'.repeat(5)}`.slice(0, 150), Severity: 'High', Tactics: 'Execution', Created: `2026-0${i + 4}-10`, ExfilOrImpactTactic: false }))
  assert.ok(tokens.every(r => r.Threat.length === 150 && !/\s/.test(r.Threat)))
  const { tableY, tableH, captionY, captionH, text } = await threatsSlide(deck('balanced', tokens).out)
  assert.ok(tableY + tableH <= captionY, 'the caption sits below the table')
  assert.ok(captionY + captionH <= BOTTOM_EMU, `the caption ends at ${((captionY + captionH) / EMU).toFixed(2)} in, past BOTTOM`)
  // A 150 character token wraps to four lines at 14 pt, so five of them only fit cut.
  for (const w of subjects) assert.ok(text.some(t => t.startsWith(`${w}_`) && t.endsWith('...') && t.length <= 113), `${w} title is cut`)
})
test('every slide and speaker note keeps to the copy rules: no semicolons, arrows or emoji, and the greater-than sign only in navigation steps', async () => {
  const { out } = deck('detailed', examples)
  const { slides, notes } = await read(out)
  const decode = s => s.replace(/&apos;/g, "'").replace(/&quot;/g, '"').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&')
  for (const text of [...slides, ...notes].map(decode)) {
    assert.ok(!/;/.test(text), text.match(/.{0,60};.{0,60}/)?.[0])
    assert.ok(!/[←-⇿➔➡]|->|=>/.test(text), text.match(/.{0,40}(?:[←-⇿➔➡]|->|=>).{0,40}/)?.[0])
    assert.ok(!/[\u{1F300}-\u{1FAFF}☀-➿]/u.test(text), 'emoji')
    assert.ok(!/</.test(text) && !/>/.test(text.replace(/[A-Za-z0-9)] > [A-Za-z]/g, '')), text.match(/.{0,60}[<>].{0,60}/)?.[0])
  }
})
test('the executive summary follows the HTML page: the posture tiers, the items that need action without the read access ask, and the new wording', async () => {
  const p = pack('balanced', examples)
  p.manifest.push({ ResultId: 'DP.8', Status: 'UNAVAILABLE', Rows: 0, ReadTimeUtc: '2026-10-08T10:00:00Z', AccessGap: true })
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ebr-deck-')), dataFile = path.join(dir, 'data.json'), out = path.join(dir, 'deck.pptx')
  fs.writeFileSync(dataFile, JSON.stringify(p))
  execFileSync(process.execPath, [path.join(__dirname, '..', 'report', 'build-report-deck.cjs'), dataFile, out])
  const { slides } = await read(out)
  const plain = s => s.replace(/\u00A0/g, ' ')
  const summary = plain(slides.find(s => s.startsWith('Executive summary')))
  for (const t of ['HOW WE REPORT POSTURE', 'TIER 1 · OUTCOMES', 'Did the program hold', 'TIER 2 · CONTROL EFFECTIVENESS', 'TIER 3 · HARDENING NEXT', 'TIER 4 · VENDOR BENCHMARK', 'Context, not the objective', 'WINS', 'WATCH', 'ITEMS THAT NEED ACTION']) assert.ok(summary.includes(t), t)
  assert.ok(!summary.includes('DECISIONS NEEDED') && !/Grant .*read access/.test(summary), 'the read access ask stays off the summary')
  assert.ok(/7 users\s+need to update their MFA method before Feb 1, 2027/.test(summary), summary.match(/.{0,30}MFA method.{0,40}/)?.[0])
  assert.ok(!/detections? correlated/.test(summary), 'the alert KPI no longer carries the detection count')
  assert.ok(/Alerts triaged Nov 1, 2025 to Sep 30, 2026/.test(summary), 'the alert KPI carries the period')
  assert.ok(/Median time to close, high severity alerts/.test(summary) && !/Confirmed threats with exfiltration/.test(summary))
  const m = build(p)
  assert.ok(summary.includes('Members without MFA') && summary.includes(`${m.tiers.hardening.find(r => r.id === 'IA.1').value}`), 'the hardening tier reads the MFA count against its population')
  assert.ok(slides.some(s => s.includes('Decisions needed') && /Grant read access/.test(s)), 'the closing slide still asks for read access')
  assert.ok(!/passwordless|passkey/i.test(slides.join(' ')), 'no passwordless wording anywhere in the deck')
})
test('a short confirmed threats table is followed by the outcome cards and the handling strip', async () => {
  const { data, out } = deck('balanced', examples)
  const { slides, notes } = await read(out)
  const slide = slides.find(s => s.startsWith('Confirmed threats') && s.includes('Log4Shell'))
  for (const t of ['Confirmed threats', 'Alerts the SOC classified as true positives from', 'Reached exfiltration or impact', 'None carried an exfiltration or impact tactic.', '1 High severity alert', 'Of the 2 confirmed alerts grouped above, at the severity Sentinel recorded.', 'EVERY CONFIRMED THREAT', '1 Detect', '2 Triage', '3 Investigate', '4 Resolve']) assert.ok(slide.includes(t), t)
  assert.ok(!/\bcontain(ed|ment)\b|resulted in|notification process/i.test(slide), 'containment, verified outcomes and notifications are never claimed')
  // The true positive count and the rows carry no status, so the cards never say the alerts were closed.
  const between = (a, b) => slide.slice(slide.indexOf(a), slide.indexOf(b))
  assert.ok(!/\bclosed\b/.test(between('Alerts the SOC classified', 'Reached exfiltration or impact')) && !/\bclosed\b/.test(between('High severity alert', 'Median time to close')), 'no true positive card claims closure')
  // One High and nine Low alerts under one title: the group reads High, the card counts one High alert of ten.
  const mixed = [{ Threat: 'Suspicious sign-in detected', Severity: 'High', Tactics: 'InitialAccess,Exfiltration', Created: '2026-08-01', ExfilOrImpactTactic: true }, ...Array.from({ length: 9 }, (_, i) => ({ Threat: 'Suspicious sign-in detected', Severity: 'Low', Tactics: 'InitialAccess', Created: `2026-08-0${i + 1}`, ExfilOrImpactTactic: false }))]
  const mixedSlide = (await read(deck('balanced', mixed).out)).slides.find(s => s.startsWith('Confirmed threats')).replace(/\u00A0/g, ' ')
  assert.ok(mixedSlide.includes('1 High severity alert') && mixedSlide.includes('Of the 10 confirmed alerts grouped above') && !mixedSlide.includes('10 High severity alerts'), mixedSlide.match(/.{0,20}High severity alert.{0,40}/)?.[0])
  assert.ok(mixedSlide.includes('1 of 3') && mixedSlide.includes('1 alert carried an exfiltration or impact tactic in Sentinel.'), 'a flagged alert reads as a tactic, not an outcome')
  // Collection-only true positives: the collector flags them, but no tactic is Exfiltration or Impact, so the card reads none.
  const collection = Array.from({ length: 3 }, (_, i) => ({ Threat: 'Suspicious inbox rule created', Severity: 'High', Tactics: 'Collection', Created: `2026-08-0${i + 1}`, ExfilOrImpactTactic: true }))
  const collectionSlide = (await read(deck('balanced', collection).out)).slides.find(s => s.startsWith('Confirmed threats')).replace(/\u00A0/g, ' ')
  assert.ok(collectionSlide.includes('0 of 3') && collectionSlide.includes('Reached exfiltration or impact') && collectionSlide.includes('None carried an exfiltration or impact tactic.'), collectionSlide.match(/.{0,10}of 3.{0,80}/)?.[0])
  // Rows without tactics (an older builder) keep the flag count and name the wider scope.
  const legacy = collection.map(({ Tactics, ...r }) => r)
  const legacyDeck = await read(deck('balanced', legacy).out)
  const legacySummary = legacyDeck.slides.find(s => s.startsWith('Executive summary')).replace(/\u00A0/g, ' ')
  assert.ok(legacySummary.includes('3 of 3') && legacySummary.includes('True positives that reached collection, exfiltration or impact') && legacySummary.includes('Collection, exfiltration or impact'), legacySummary.match(/.{0,20}collection.{0,60}/i)?.[0])
  assert.ok(!legacyDeck.slides.some(s => /Attack stage/.test(s)), 'rows without tactics have no examples table')
  const m = build(data)
  for (const n of [...m.presenter, ...m.review]) assert.ok(!notes.join(' ').includes(n.text), `speaker notes carry "${n.title}"`)
})
test('the control posture slide highlights the headline measure column and drops the not-gathered note', async () => {
  const zip = await JSZip.loadAsync(fs.readFileSync(deck('balanced').out))
  const xmls = await Promise.all(Object.keys(zip.files).filter(n => /^ppt\/slides\/slide\d+\.xml$/.test(n)).map(n => zip.file(n).async('string')))
  const xml = xmls.find(x => x.includes('name="Headline measure band"'))
  assert.ok(xml, 'the band behind the headline measure column')
  const text = (xml.match(/<a:t>[^<]*<\/a:t>/g) || []).map(t => t.slice(5, -6)).join(' ')
  assert.ok(!/not gathered\. See the appendix|Every control was gathered/.test(text), 'the not-gathered note is gone')
  assert.ok(/Headline measure/.test(text))
})
test('the MFA method update slide replaces the passwordless transition', async () => {
  const { slides, notes } = await read(deck('brief').out)
  const slide = slides.find(s => s.startsWith('MFA method update'))
  assert.ok(slide, 'the slide is there at brief depth')
  for (const t of ['days to move 7 users', 'USERS BY SIGN-IN METHOD, LAST 30 DAYS', 'Text message or voice', 'Notify the affected users', 'Register a stronger method', 'Remove the retiring methods', 'Confirm readiness early', 'OUTCOME']) assert.ok(slide.replace(/\u00A0/g, ' ').includes(t), t)
  assert.ok(!slides.some(s => /Passwordless transition|Passkeys/.test(s)) && !/passkey|passwordless/i.test([...slides, ...notes].join(' ')))
})
test('the posture appendix draws the Defender for Cloud score by month and states the movement from its starting percentage', async () => {
  const p = pack('detailed')
  p.manifest.push({ ResultId: 'POS.7', Status: 'OK', Rows: 3, ReadTimeUtc: '2026-10-08T10:00:00Z' })
  p.results['POS.7'] = [{ Month: '2026-07-01', Current: 18, Max: 40, Percent: 45 }, { Month: '2026-08-01', Current: 19, Max: 40, Percent: 47.5 }, { Month: '2026-10-01', Current: 20, Max: 40, Percent: 50 }]
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ebr-deck-')), dataFile = path.join(dir, 'data.json'), out = path.join(dir, 'deck.pptx')
  fs.writeFileSync(dataFile, JSON.stringify(p))
  execFileSync(process.execPath, [path.join(__dirname, '..', 'report', 'build-report-deck.cjs'), dataFile, out])
  const zip = await JSZip.loadAsync(fs.readFileSync(out))
  const charts = await Promise.all(Object.keys(zip.files).filter(n => /^ppt\/charts\/chart\d+\.xml$/.test(n)).map(n => zip.file(n).async('string')))
  assert.ok(charts.some(c => c.includes('<c:lineChart>')), 'a line chart for the score by month')
  const { slides } = await read(out)
  const posture = slides.find(s => s.startsWith('Tenant and cloud security posture')).replace(/\u00A0/g, ' ')
  assert.ok(posture.includes('Up 5 points since Jul 2026, from 45%.'), posture.match(/.{0,20}Up .{0,50}/)?.[0])
  assert.ok(!/of 40 points|points across/.test(posture), 'the points available are never stated')
  assert.ok(posture.includes('DEFENDER FOR CLOUD · AZURE RESOURCE ESTATE'))
})
