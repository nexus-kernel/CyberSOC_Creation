// PowerPoint edition of the report (report/build-report-deck.cjs): pages follow the depth, the
// copy rules hold, and speaker notes never carry the presenter notes.
const { test } = require('node:test')
const assert = require('node:assert/strict')
const fs = require('node:fs')
const os = require('node:os')
const path = require('node:path')
const { execFileSync } = require('node:child_process')
const { build } = require('../report/report-model.js')
const { JSZip, lines } = require('../report/deck-common.cjs')

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
// The impact statement every surface prints until the context file carries a reviewed Impact record.
const GATE = 'Based on the tactics Sentinel recorded on the alerts, none of the confirmed threats carried an exfiltration or impact tactic. Additional investigation evidence is required to confirm whether any data exposure or business impact occurred.'
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
function deckOf(data) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ebr-deck-')), dataFile = path.join(dir, 'data.json'), out = path.join(dir, 'deck.pptx')
  fs.writeFileSync(dataFile, JSON.stringify(data))
  execFileSync(process.execPath, [path.join(__dirname, '..', 'report', 'build-report-deck.cjs'), dataFile, out])
  return out
}
// DR.10 reads the last 30 days and the win sits beside the period's figures, so the win names its window and the
// period's unclassified closures from OUT.1 (Oct 16, 2026).
test('the DR.10 win names its window and the unclassified closures, and the operations slide says closed, never resolved', async () => {
  const plain = s => s.replace(/ /g, ' ')
  const data = pack('balanced')
  data.manifest.push({ ResultId: 'DR.10', Status: 'OK', Rows: 1, ReadTimeUtc: '2026-10-08T10:00:00Z' }); data.results['DR.10'] = [{ Closed: 40, Documented: 40 }]
  const { slides, notes } = await read(deckOf(data))
  const wins = plain(slides.find(s => /^(Summary )?(Quarter wins|Wins this period)/.test(plain(s))) || slides.find(s => /Wins this period|Quarter wins/.test(s)) || '')
  assert.ok(wins.includes('40 of 40') && wins.includes('alerts closed in the last 30 days with a documented disposition'), wins)
  assert.ok(wins.includes('Classification and closing comment. 5 alerts created from Nov 1, 2025 to Sep 30, 2026 and closed by collection carry no classification.'), wins)
  const ops = plain(slides.find(s => /HOW CLOSED ALERTS WERE/i.test(s)) || '')
  assert.ok(/HOW CLOSED ALERTS WERE CLASSIFIED/i.test(ops) && !/resolved/i.test(ops), ops)
  assert.ok(![...slides, ...notes].some(t => /every alert|worked to a disposition/i.test(plain(t))), [...slides, ...notes].map(plain).join(' ').match(/.{0,80}(every alert|worked to a disposition).{0,80}/i)?.[0])
  // With nothing unclassified the sub-line names the measure alone, and the label still carries the window.
  data.results['OUT.1'] = [{ Raised: 100, Closed: 80, Open: 20, TruePositive: 3, ClosedUnclassified: 0 }]
  const clean = plain((await read(deckOf(data))).slides.find(s => /Wins this period|Quarter wins/.test(s)) || '')
  assert.ok(clean.includes('alerts closed in the last 30 days with a documented disposition Classification and closing comment.') && !clean.includes('carry no classification'), clean)
})
// A reviewed OpenAlertNote split is cited on the operations slide's own notes, not only on the pillar notes.
test('the operations slide splits the open alerts from a reviewed record and cites it in its notes', async () => {
  const plain = s => s.replace(/\u00A0/g, ' ')
  const data = pack('balanced')
  data.parameters.TenantId = 't'
  data.context = { ClientName: 'Example', TenantId: 't', OpenAlertNote: { AwaitingClient: 12, InProgress: 8, Reviewed: '2026-10-10', Reference: 'ZD 9900200', WindowStart: '2025-11-01', WindowEnd: '2026-09-30' } }
  const { slides, notes } = await read(deckOf(data))
  const index = slides.findIndex(s => /HOW CLOSED ALERTS WERE CLASSIFIED/i.test(s))
  assert.ok(index >= 0, 'the operations slide')
  assert.ok(plain(slides[index]).includes('20 more were open at collection. Of these, 12 were awaiting client action or confirmation and 8 were still in progress with Atmosera.'), plain(slides[index]))
  const opsNotes = plain(notes[index])
  assert.ok(opsNotes.includes('Of the alerts open at collection, 12 were awaiting client action or confirmation and 8 were still in progress with Atmosera.') && opsNotes.includes('Reviewed open alert status ZD 9900200, Oct 10, 2026, from the reviewed context file.'), opsNotes)
  assert.ok(![...slides, ...notes].some(t => /reporting cutoff/i.test(t)))
})
test('the grounding slides appear at balanced depth and carry the pillar narratives, the priority workstreams and the scope', async () => {
  const { data, out } = deck('balanced', examples)
  const m = build(data)
  const { slides, notes } = await read(out)
  // Figures and dates are glued with non-breaking spaces on the slide, so the comparison reads them as spaces.
  const plain = s => s.replace(/\u00A0/g, ' ')
  const pillars = plain(slides.find(s => s.startsWith('Measured outcomes by pillar')) || '')
  assert.ok(pillars, 'the pillar outcomes slide')
  for (const p of m.pillars) assert.ok(pillars.includes(p.name) && pillars.includes(p.headline), p.name)
  // The pack holds open and unclassified alerts, so the disposition statement leads with the closed and open counts
  // on the slide and in the notes, and no slide or note says every alert or worked to a disposition.
  assert.equal(m.pillars.find(p => p.name === 'Detection and response').headline, '80 of 100 alerts closed, 20 open at collection')
  assert.ok(![...slides, ...notes].some(t => /every alert|worked to a disposition/i.test(plain(t))), [...slides, ...notes].map(plain).join(' ').match(/.{0,60}(every alert|worked to a disposition).{0,60}/i)?.[0])
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
test('the pillar slide never cuts the endpoint reconciliation when EW.1-GAPS reports machines, never lets a row run into the next, and an E with exceptions never reads as every machine', async () => {
  const gap = (Reason, Devices, extra = {}) => ({ Reason, Product: '', Devices, Eligible: true, Covered: false, Onboarded: 0, CanBeOnboarded: 0, NotSeen: 0, Other: 0, ...extra })
  const crowded = (ew1, gaps) => {
    const p = pack('balanced')
    const add = (id, rows) => { p.manifest.push({ ResultId: id, Status: 'OK', Rows: rows.length, ReadTimeUtc: '2026-10-08T10:00:00Z' }); p.results[id] = rows }
    add('EW.1', [{ Scope: 'Azure VM', OSPlatform: 'WindowsServer2022', Onboarded: 88, SensorActive: 81, ...ew1 }])
    add('EW.1-GAPS', gaps)
    add('DR.5', [{ Scope: 'Azure VM', Onboarded: 88, Assessed: 85 }])
    add('DP.4', [{ Resources: 40, WithEncryptionAtHost: 38 }])
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ebr-deck-')), dataFile = path.join(dir, 'data.json'), out = path.join(dir, 'deck.pptx')
    fs.writeFileSync(dataFile, JSON.stringify(p))
    execFileSync(process.execPath, [path.join(__dirname, '..', 'report', 'build-report-deck.cjs'), dataFile, out])
    const m = build(p)
    return { out, endpoint: m.pillars.find(x => x.name === 'Endpoint and workload') }
  }
  // Every row's story box as the deck sizes it: its width, its text, whether a measure sits beside it, and whether its
  // headline and body fit the row by the deck's own line estimate. Figures and units are glued with non-breaking
  // spaces on the slide, so the text reads them as spaces. The continuation slide's text, when there is one.
  const pillarSlides = async out => {
    const zip = await JSZip.loadAsync(fs.readFileSync(out))
    const xmls = await Promise.all(Object.keys(zip.files).filter(n => /^ppt\/slides\/slide\d+\.xml$/.test(n)).map(n => zip.file(n).async('string')))
    const xml = xmls.find(x => x.includes('name="Endpoint and workload outcome story"'))
    assert.ok(xml, 'the pillar outcomes slide')
    const room = (7.0 - 1.75) / 5 - 0.14, rows = {}
    for (const sh of xml.split('<p:sp>').filter(x => / outcome story"/.test(x))) {
      const name = sh.match(/name="([^"]*) outcome story"/)[1], width = Number(sh.match(/<a:ext cx="(\d+)"/)[1]) / EMU
      const [head, body] = [...sh.matchAll(/<a:rPr[^>]*sz="(\d+)"[^>]*>[\s\S]*?<a:t>([^<]*)<\/a:t>/g)].map(r => ({ size: Number(r[1]) / 100, text: r[2].replace(/\u00A0/g, ' ') }))
      const need = lines(head.text, width, head.size, true) * 0.18 + lines(body.text, width, body.size) * body.size * 0.0165 + 0.05
      rows[name] = { width, story: `${head.text} ${body.text}`, fits: need <= room + 1e-9, need, measure: xml.includes(`name="${name} measure value"`) }
    }
    const next = xmls.find(x => x.includes('Measured outcomes by pillar, continued'))
    return { rows, endpoint: rows['Endpoint and workload'], continued: next ? (next.match(/<a:t>[^<]*<\/a:t>/g) || []).map(t => t.slice(5, -6)).join(' ').replace(/\u00A0/g, ' ') : null }
  }
  const allFit = slide => { for (const [name, r] of Object.entries(slide.rows)) assert.ok(r.fits, `${name} needs ${r.need.toFixed(3)} in and runs into the next row`) }
  const keptOf = endpoint => endpoint.keep.split(/(?<=\.) (?=[A-Z0-9])/)
  // Seven onboarded machines without an active sensor and one with no endpoint detection: 88 of 89 at E.
  let { out, endpoint } = crowded({ Devices: 89, CanBeOnboarded: 1 }, [gap('Onboarded, sensor not active', 7, { Onboarded: 7 }), gap('Not onboarded, no endpoint detection found', 1, { CanBeOnboarded: 1 })])
  assert.equal(endpoint.headline, 'Endpoint detection covers 88 of 89 eligible Azure virtual machines, with 1 remaining')
  let slide = await pillarSlides(out)
  allFit(slide)
  for (const kept of keptOf(endpoint)) assert.ok(slide.endpoint.story.includes(kept), `the slide keeps "${kept}"`)
  assert.match(slide.endpoint.story, /8 Azure virtual machines are not reporting through an active Defender for Endpoint sensor\. 7 are onboarded with a sensor that is not active and 1 is not onboarded and carries no endpoint detection product\./)
  assert.ok(slide.endpoint.story.startsWith(endpoint.headlineShort), 'the row takes the short headline before it touches a kept sentence')
  assert.ok(!/\bevery\b/i.test(slide.endpoint.story), slide.endpoint.story)
  assert.ok(!slide.endpoint.story.includes('Encryption at host is enabled'), 'a sentence that is not kept goes first')
  assert.ok(slide.endpoint.measure && slide.endpoint.width < 6.5 && !slide.continued, 'the row fits with the short headline and keeps its measure')
  // Every reason type at once: the row gives the measure column to the story, still cutting nothing kept.
  ;({ out, endpoint } = crowded({ Devices: 100, CanBeOnboarded: 6, Unsupported: 3, InsufficientInfo: 2 }, [
    gap('Onboarded, sensor not active', 7, { Onboarded: 7 }), gap('Not onboarded, no endpoint detection found', 1, { CanBeOnboarded: 1 }),
    gap('Covered by a third-party endpoint detection product', 2, { Product: 'CrowdStrike Falcon', Covered: true, CanBeOnboarded: 2 }), gap('Network virtual appliance, cannot run a sensor', 1, { Eligible: false, CanBeOnboarded: 1 }),
    gap('Deallocated or stopped at collection', 2, { Eligible: false, CanBeOnboarded: 2 }), gap('Operating system not supported by the sensor', 3, { Eligible: false }),
    gap('Discovered only, insufficient information', 2, { Eligible: false }), gap('Not discovered by Defender for Endpoint', 3, { NotSeen: 3 })
  ]))
  assert.match(endpoint.keep, /21 Azure virtual machines are not reporting.* and 3 have never been discovered by Defender for Endpoint\.$/)
  slide = await pillarSlides(out)
  allFit(slide)
  for (const kept of keptOf(endpoint)) assert.ok(slide.endpoint.story.includes(kept), `the slide keeps "${kept}"`)
  assert.ok(!slide.endpoint.measure && slide.endpoint.width > 9.5 && !slide.continued, `the story takes the measure column (${slide.endpoint.width.toFixed(2)} in)`)
  // The largest supported result: the seven other reasons plus the third-party reason split across all nine product
  // labels the collector names, 16 groups (Void's draft review). Even 9 pt across the row cannot hold it, so the row
  // keeps its measure and the kept sentences that fit, points on, and the next slide carries the full reading.
  const PRODUCTS = ['CrowdStrike Falcon', 'SentinelOne', 'Carbon Black', 'Cortex XDR', 'Cybereason', 'Tanium', 'Trellix', 'Cylance', 'a third-party endpoint detection product']
  ;({ out, endpoint } = crowded({ Devices: 120, CanBeOnboarded: 16, Unsupported: 3, InsufficientInfo: 2 }, [
    gap('Onboarded, sensor not active', 7, { Covered: true, Onboarded: 7 }), gap('Not onboarded, no endpoint detection found', 1, { CanBeOnboarded: 1 }),
    ...PRODUCTS.map(Product => gap('Covered by a third-party endpoint detection product', 1, { Product, Covered: true, CanBeOnboarded: 1 })),
    gap('Network virtual appliance, cannot run a sensor', 1, { Eligible: false, CanBeOnboarded: 1 }), gap('Deallocated or stopped at collection', 2, { Eligible: false, CanBeOnboarded: 2 }),
    gap('Operating system not supported by the sensor', 3, { Eligible: false, Other: 3 }), gap('Discovered only, insufficient information', 2, { Eligible: false, Other: 2 }),
    gap('Not discovered by Defender for Endpoint', 3, { NotSeen: 3 })
  ]))
  assert.ok(PRODUCTS.every(product => endpoint.keep.includes(`1 is covered by ${product}`)), endpoint.keep)
  slide = await pillarSlides(out)
  allFit(slide)
  assert.ok(slide.endpoint.measure && slide.endpoint.width < 6.5, 'the row keeps its standard layout and its measure')
  assert.ok(slide.endpoint.story.startsWith(endpoint.headlineShort) && slide.endpoint.story.includes(keptOf(endpoint)[0]), slide.endpoint.story)
  assert.ok(slide.endpoint.story.endsWith('The full reading continues on the next slide.'), slide.endpoint.story)
  assert.ok(slide.continued, 'the continuation slide follows')
  assert.ok(slide.continued.includes(endpoint.headline), 'the continuation carries the full headline')
  for (const kept of keptOf(endpoint)) assert.ok(slide.continued.includes(kept), `the continuation keeps "${kept}"`)
  assert.ok(!/\bevery\b/i.test(slide.endpoint.story + slide.continued), 'no absolute word on either slide')
})
// Issue #24: a pack whose patch cadence reads 2 of 2 with 18 machines excluded by tag, and one without a small sample.
// The register flags the row, and every tier total on the deck names the small sample beside it and still fits.
test('the deck names a small sample beside every tier total and flags it on the register, and every box still fits', async () => {
  const build = (withSmall, dense = false) => {
    const p = pack('balanced')
    const set = (id, rows) => { p.manifest = p.manifest.filter(r => r.ResultId !== id); p.manifest.push({ ResultId: id, Status: 'OK', Rows: rows.length, ReadTimeUtc: '2026-10-08T10:00:00Z' }); p.results[id] = rows }
    set('DP.2', [{ Vaults: 40, SoftDelete: 40, PurgeProtection: 0, RbacAuth: 30 }])
    set('EW.10', withSmall ? [{ Machines: 2, WithinCadence: 2 }] : [{ Machines: 70, WithinCadence: 68 }])
    if (withSmall) set('EW.10-EXCLUDED', [{ Machines: dense ? 1 : 18 }])
    // A three-machine tenant: every endpoint ratio is on a small sample at once, the densest register the flag makes.
    if (dense) {
      const vm = (Devices, Compliant, extra = {}) => [{ Scope: 'Azure VM', OSPlatform: 'WindowsServer2022', Devices, Compliant, ...extra }]
      set('EW.1', [{ Scope: 'Azure VM', OSPlatform: 'WindowsServer2022', Devices: 3, Onboarded: 3, CanBeOnboarded: 0, SensorActive: 3 }])
      set('DR.5', [{ Scope: 'Azure VM', Onboarded: 3, Assessed: 3 }])
      set('EW.3', vm(3, 3, { ConfigurationName: 'Turn on real-time protection' })); set('EW.15', vm(3, 3)); set('EW.16', vm(3, 2)); set('EW.12', vm(3, 2)); set('EW.14', vm(3, 3))
      set('EW.7', [{ VMs: 3, TrustedLaunchOrCvm: 2 }]); set('DP.4', [{ Resources: 3, WithEncryptionAtHost: 3 }]); set('DP.5b', [{ VmsWithoutBackup: 1 }])
    }
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ebr-deck-')), dataFile = path.join(dir, 'data.json'), out = path.join(dir, 'deck.pptx')
    fs.writeFileSync(dataFile, JSON.stringify(p))
    execFileSync(process.execPath, [path.join(__dirname, '..', 'report', 'build-report-deck.cjs'), dataFile, out])
    return out
  }
  const plain = x => (x.match(/<a:t>[^<]*<\/a:t>/g) || []).map(t => t.slice(5, -6)).join(' ').replace(/ /g, ' ')
  const box = (xml, name) => { const hit = xml.match(new RegExp(`name="${name}"[\\s\\S]*?<a:off x="(\\d+)" y="(\\d+)"/><a:ext cx="(\\d+)" cy="(\\d+)"/>[\\s\\S]*?</p:sp>`)); return hit && { y: Number(hit[2]) / EMU, h: Number(hit[4]) / EMU, text: plain(hit[0]) } }
  const slides = async out => { const zip = await JSZip.loadAsync(fs.readFileSync(out)); return Promise.all(Object.keys(zip.files).filter(n => /^ppt\/slides\/slide\d+\.xml$/.test(n)).map(n => zip.file(n).async('string'))) }
  const xmls = await slides(build(true))
  const all = xmls.map(plain).join(' ')
  // The register: the flag rides on the figure, the populations on the detail line, and the tier count names it.
  const reg = xmls.find(x => x.includes('Operating system findings remediated within the patch cadence register label'))
  assert.match(plain(reg), /Operating system findings remediated within the patch cadence\s+2 assessed · 18 excluded by tag\s+2 of 2\s+· small sample/)
  assert.equal(box(reg, 'Operating system findings remediated within the patch cadence register value').text.replace(/\s+/g, ' '), '2 of 2 · small sample')
  assert.equal(box(reg, 'Endpoint and workload foundational count').text, '1 of 1 (1 on a small sample)')
  for (const x of xmls.filter(x => x.includes('register rule'))) for (const r of x.matchAll(/name="([^"]*) register rule"[\s\S]*?<a:off x="\d+" y="(\d+)"\/>/g)) assert.ok(Number(r[2]) <= 7.2 * EMU, `"${r[1]}" ends at ${(Number(r[2]) / EMU).toFixed(2)} in`)
  // The posture matrix: the pillar count and the all pillars total carry a second line, above the meter.
  const posture = xmls.find(x => x.includes('All pillars foundational'))
  const count = box(posture, 'Endpoint and workload foundational count'), meter = box(posture, 'Endpoint and workload foundational track')
  assert.equal(count.text, '1 of 1 1 on a small sample')
  assert.ok(count.y + count.h <= meter.y + 0.001, `the count ends at ${(count.y + count.h).toFixed(2)} in, the meter starts at ${meter.y.toFixed(2)} in`)
  assert.match(box(posture, 'All pillars foundational').text, /^\d+ of \d+ 1 on a small sample$/)
  assert.ok(!/on a small sample/.test(box(posture, 'All pillars defense').text))
  assert.match(plain(posture), /foundational controls are enforced \(1 on a small sample\)\./, 'the takeaway')
  // The executive summary tier band, the summary column or KPI, and the pillar outcome line.
  assert.match(all, /Foundational controls \(1 on a small sample\)/)
  assert.match(all, /foundational controls enforced across five pillars \(1 on a small sample\)|Across five pillars, 1 on a small sample/)
  assert.match(all, /\d+ of \d+ foundational enforced, 1 on a small sample/)
  // Without a small sample nothing is annotated.
  assert.ok(!/small sample/.test((await slides(build(false))).map(plain).join(' ')))
  // The dense tenant: ten flagged endpoint rows, and every register row still ends inside 7.2 in. Before the flag moved
  // to the value column its label suffix wrapped the long endpoint labels and the A1 register ended near 7.35 in.
  const dense = await slides(build(true, true))
  const a1 = dense.find(x => x.includes('Operating system findings remediated within the patch cadence register label'))
  assert.equal([...a1.matchAll(/register value"[\s\S]*?<\/p:sp>/g)].filter(v => plain(v[0]).includes('small sample')).length, 10)
  for (const x of dense.filter(x => x.includes('register rule'))) for (const r of x.matchAll(/name="([^"]*) register rule"[\s\S]*?<a:off x="\d+" y="(\d+)"\/>/g)) assert.ok(Number(r[2]) <= 7.2 * EMU, `dense: "${r[1]}" ends at ${(Number(r[2]) / EMU).toFixed(2)} in`)
})
test('the control register counts the exceptions of a control at E on its label line and every column still fits', async () => {
  const p = pack('balanced')
  const set = (id, rows) => { p.manifest = p.manifest.filter(r => r.ResultId !== id); p.manifest.push({ ResultId: id, Status: 'OK', Rows: rows.length, ReadTimeUtc: '2026-10-08T10:00:00Z' }); p.results[id] = rows }
  // Nearly every ratio reading at E with something left out, the densest the register gets.
  set('IA.1', [{ UserType: 'Member', UsersSignedIn: 194, UsersChallenged: 180 }])
  set('EW.1', [{ Scope: 'Azure VM', OSPlatform: 'WindowsServer2022', Devices: 89, Onboarded: 88, CanBeOnboarded: 1, SensorActive: 81 }])
  set('DR.5', [{ Scope: 'Azure VM', Onboarded: 88, Assessed: 85 }])
  set('DP.4', [{ Resources: 40, WithEncryptionAtHost: 38 }])
  set('DP.5b', [{ VmsWithoutBackup: 2 }])
  set('EW.10', [{ Machines: 70, WithinCadence: 68 }])
  set('NB.4', [{ Sites: 48, HttpsOnly: 47 }])
  set('NB.1', [{ WorkloadSubnets: 30, Segmented: 29 }])
  set('DP.1', [{ Accounts: 37, SecureTransfer: 36, MinTls12: 36, AnonymousBlobOff: 36, PublicNetworkOff: 35 }])
  set('DP.1-CONTAINERS', [{ Containers: 78, PrivateContainers: 77, ExposedContainers: 0, AccountsExposed: 0, AccountsUnread: 0 }])
  set('DP.2', [{ Vaults: 20, SoftDelete: 19, PurgeProtection: 19, RbacAuth: 19 }])
  set('DR.9', [{ Scope: 'All workspaces', Metric: 'Total rules', Value: 386 }, { Scope: 'All workspaces', Metric: 'Enabled rules', Value: 379 }])
  set('DR.10', [{ Closed: 100, Documented: 97 }])
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ebr-deck-')), dataFile = path.join(dir, 'data.json'), out = path.join(dir, 'deck.pptx')
  fs.writeFileSync(dataFile, JSON.stringify(p))
  execFileSync(process.execPath, [path.join(__dirname, '..', 'report', 'build-report-deck.cjs'), dataFile, out])
  const zip = await JSZip.loadAsync(fs.readFileSync(out))
  const xmls = (await Promise.all(Object.keys(zip.files).filter(n => /^ppt\/slides\/slide\d+\.xml$/.test(n)).map(n => zip.file(n).async('string')))).filter(x => x.includes('register rule'))
  assert.equal(xmls.length, 3, 'the three register slides')
  const text = xmls.map(x => (x.match(/<a:t>[^<]*<\/a:t>/g) || []).map(t => t.slice(5, -6)).join(' ')).join(' ').replace(/\u00A0/g, ' ')
  for (const [label, count] of [['Azure virtual machines reporting to endpoint detection', '1 exception'], ['Endpoint sensors active on onboarded Azure virtual machines', '7 exceptions'], ['Key Vault soft delete', '1 exception'], ['Multifactor authentication required at sign-in', '14 exceptions']]) {
    assert.match(text, new RegExp(`${label}\\s+· ${count}\\b`), `${label} carries ${count}`)
  }
  // Analytics rules are a presence check: 379 of 386 enabled reads In force, and disabled rules are no exceptions.
  assert.match(text, /Analytics rules enabled in every Sentinel workspace In force/)
  // Every row ends inside the column the register sizes for.
  for (const xml of xmls) for (const r of xml.matchAll(/name="([^"]*) register rule"[\s\S]*?<a:off x="\d+" y="(\d+)"\/>/g)) assert.ok(Number(r[2]) <= 7.2 * EMU, `"${r[1]}" ends at ${(Number(r[2]) / EMU).toFixed(2)} in`)
  const { notes } = await read(out)
  assert.ok(notes.some(n => n.includes('Azure virtual machines reporting to endpoint detection: 88 of 89, 1 exception.')), 'the speaker notes say the count')
})
test('Conditional Access controls in force carry the excluded accounts that signed in on the register label line, and every column still fits (issue #27)', async () => {
  const p = pack('balanced')
  const set = (id, rows) => { p.manifest = p.manifest.filter(r => r.ResultId !== id); p.manifest.push({ ResultId: id, Status: 'OK', Rows: rows.length, ReadTimeUtc: '2026-10-08T10:00:00Z' }); p.results[id] = rows }
  const ca = (Flow, o = {}) => ({ Flow, PolicyRead: true, PolicyState: 'Enforced', EnforcedPolicies: 1, ExcludedIdentities: 12, DetailRead: true, SignIns: 0, SucceededExcluded: 0, AccountsExcluded: 0, SucceededUngoverned: 0, AccountsUngoverned: 0, ...o })
  // The densest identity column: every Conditional Access row in force with excluded sign-ins, beside ratio exceptions elsewhere.
  set('IA.1', [{ UserType: 'Member', UsersSignedIn: 194, UsersChallenged: 180 }])
  set('IA.1-ADMINPORTAL', [{ UserType: 'Member', Users: 12, UsersChallenged: 12 }])
  set('IA.3', [{ ClientAppUsed: 'Exchange ActiveSync', Attempts: 40, Succeeded: 4, BlockedByCa: 30, Users: 2 }])
  set('IA.3-DEVICECODE', [{ Attempts: 3, Succeeded: 3, BlockedByCa: 0, Users: 2, Apps: 1, InForce: false }])
  set('IA.8-CA', [ca('MFA at sign-in', { SucceededExcluded: 14, AccountsExcluded: 12 }), ca('Admin portals'), ca('Legacy authentication', { SucceededExcluded: 4, AccountsExcluded: 2 }), ca('Device code', { SucceededExcluded: 3, AccountsExcluded: 2 }), ca('Location')])
  set('EW.1', [{ Scope: 'Azure VM', OSPlatform: 'WindowsServer2022', Devices: 89, Onboarded: 88, CanBeOnboarded: 1, SensorActive: 81 }])
  set('DR.5', [{ Scope: 'Azure VM', Onboarded: 88, Assessed: 85 }])
  set('EW.10', [{ Machines: 70, WithinCadence: 68 }])
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ebr-deck-')), dataFile = path.join(dir, 'data.json'), out = path.join(dir, 'deck.pptx')
  fs.writeFileSync(dataFile, JSON.stringify(p))
  execFileSync(process.execPath, [path.join(__dirname, '..', 'report', 'build-report-deck.cjs'), dataFile, out])
  const zip = await JSZip.loadAsync(fs.readFileSync(out))
  const xmls = (await Promise.all(Object.keys(zip.files).filter(n => /^ppt\/slides\/slide\d+\.xml$/.test(n)).map(n => zip.file(n).async('string')))).filter(x => x.includes('register rule'))
  const text = xmls.map(x => (x.match(/<a:t>[^<]*<\/a:t>/g) || []).map(t => t.slice(5, -6)).join(' ')).join(' ').replace(/\u00A0/g, ' ')
  for (const [label, count] of [['Multifactor authentication required at sign-in', '12 excluded accounts signed in'], ['Legacy authentication blocked', '2 excluded accounts signed in'], ['Device code flow sign-ins blocked', '2 excluded accounts signed in']]) {
    assert.match(text, new RegExp(`${label}\\s+· ${count}\\b`), `${label} carries ${count}`)
  }
  assert.match(text, /Azure virtual machines reporting to endpoint detection\s+· 1 exception\b/, 'ratio exceptions read beside them')
  assert.ok(!/approved/i.test(text), 'no approved wording on the register')
  for (const xml of xmls) for (const r of xml.matchAll(/name="([^"]*) register rule"[\s\S]*?<a:off x="\d+" y="(\d+)"\/>/g)) assert.ok(Number(r[2]) <= 7.2 * EMU, `"${r[1]}" ends at ${(Number(r[2]) / EMU).toFixed(2)} in`)
  const { notes } = await read(out)
  assert.ok(notes.some(n => n.includes('Device code flow sign-ins blocked: In force, 2 excluded accounts signed in. ') && n.includes('3 successful sign-ins came from 2 accounts excluded from the policy. Atmosera reviews these exclusions with your team at each business review.')), 'the speaker notes say the count and the review sentence')
})
test('in a federated tenant the register detail line and the pillar slide carry the MFA split, and every row still fits', async () => {
  const p = pack('balanced')
  const set = (id, rows) => { p.manifest = p.manifest.filter(r => r.ResultId !== id); p.manifest.push({ ResultId: id, Status: 'OK', Rows: rows.length, ReadTimeUtc: '2026-10-08T10:00:00Z' }); p.results[id] = rows }
  // The densest register as above, with MFA at sign-in at E among the members evaluated.
  set('IA.1', [{ UserType: 'Member', UsersSignedIn: 400, UsersChallenged: 180, UsersExternalMfa: 180, FederatedMfaAtLeastOnce: 180, FederatedWithoutMfa: 0, NoMfaOnlyUnevaluated: 206, MfaSessionLinkedOnly: 25 }])
  set('IA.1-FEDERATION', [{ FederatedDomains: 2, ConfigsRead: 2, Provider: 'Okta', MfaBehavior: 'acceptIfMfaDoneByFederatedIdp' }])
  set('EW.1', [{ Scope: 'Azure VM', OSPlatform: 'WindowsServer2022', Devices: 89, Onboarded: 88, CanBeOnboarded: 1, SensorActive: 81 }])
  set('DR.5', [{ Scope: 'Azure VM', Onboarded: 88, Assessed: 85 }])
  set('DP.4', [{ Resources: 40, WithEncryptionAtHost: 38 }])
  set('EW.10', [{ Machines: 70, WithinCadence: 68 }])
  set('NB.4', [{ Sites: 48, HttpsOnly: 47 }])
  set('DR.10', [{ Closed: 100, Documented: 97 }])
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ebr-deck-')), dataFile = path.join(dir, 'data.json'), out = path.join(dir, 'deck.pptx')
  fs.writeFileSync(dataFile, JSON.stringify(p))
  execFileSync(process.execPath, [path.join(__dirname, '..', 'report', 'build-report-deck.cjs'), dataFile, out])
  const zip = await JSZip.loadAsync(fs.readFileSync(out))
  const xmls = await Promise.all(Object.keys(zip.files).filter(n => /^ppt\/slides\/slide\d+\.xml$/.test(n)).map(n => zip.file(n).async('string')))
  const plain = x => (x.match(/<a:t>[^<]*<\/a:t>/g) || []).map(t => t.slice(5, -6)).join(' ').replace(/\u00A0/g, ' ')
  // The register: the split on the detail line under the label, and every row inside its column and its rule.
  const reg = xmls.find(x => x.includes('Multifactor authentication required at sign-in register label'))
  assert.ok(reg, 'the identity register slide')
  assert.match(plain(reg), /Multifactor authentication required at sign-in\s+· 14 exceptions\s+194 of 400 members evaluated · 25 inferred from an earlier MFA sign-in in the same session\s+180 of 194/)
  for (const xml of xmls.filter(x => x.includes('register rule'))) for (const r of xml.matchAll(/name="([^"]*) register rule"[\s\S]*?<a:off x="\d+" y="(\d+)"\/>/g)) assert.ok(Number(r[2]) <= 7.2 * EMU, `"${r[1]}" ends at ${(Number(r[2]) / EMU).toFixed(2)} in`)
  const boxes = [...reg.matchAll(/name="([^"]*) register label"[\s\S]*?<a:off x="\d+" y="(\d+)"\/><a:ext cx="\d+" cy="(\d+)"\/>/g)].map(m => ({ label: m[1], y: Number(m[2]), h: Number(m[3]) }))
  const rules = [...reg.matchAll(/name="([^"]*) register rule"[\s\S]*?<a:off x="\d+" y="(\d+)"\/>/g)].map(m => ({ label: m[1], y: Number(m[2]) }))
  for (const b of boxes) { const r = rules.find(x => x.label === b.label); assert.ok(r && b.y + b.h <= r.y + 1, `${b.label} ends at its own rule`) }
  // The pillar slide keeps the split, on the row or on the continuation slide, and no row runs into the next.
  const m = build(p), identity = m.pillars.find(x => x.name === 'Identity and access')
  const kept = identity.keep.split(/(?<=\.) (?=[A-Z0-9])/)
  assert.deepEqual(kept, ['Of 400 members who signed in over the last 30 days, 194 could be evaluated.', '180 of them showed multifactor authentication, 155 on their own sign-ins and 25 inferred from an earlier MFA sign-in in the same session.', '206 members signed in only through device sessions that no Conditional Access policy checked and are not evaluated.'])
  const pillarXml = xmls.find(x => x.includes('name="Identity and access outcome story"'))
  const room = (7.0 - 1.75) / 5 - 0.14
  for (const sh of pillarXml.split('<p:sp>').filter(x => / outcome story"/.test(x))) {
    const name = sh.match(/name="([^"]*) outcome story"/)[1], width = Number(sh.match(/<a:ext cx="(\d+)"/)[1]) / EMU
    const [head, body] = [...sh.matchAll(/<a:rPr[^>]*sz="(\d+)"[^>]*>[\s\S]*?<a:t>([^<]*)<\/a:t>/g)].map(r => ({ size: Number(r[1]) / 100, text: r[2].replace(/\u00A0/g, ' ') }))
    const need = lines(head.text, width, head.size, true) * 0.18 + lines(body.text, width, body.size) * body.size * 0.0165 + 0.05
    assert.ok(need <= room + 1e-9, `${name} needs ${need.toFixed(3)} in and runs into the next row`)
  }
  const story = plain(pillarXml.split('<p:sp>').find(x => x.includes('name="Identity and access outcome story"')))
  const continued = xmls.find(x => x.includes('Measured outcomes by pillar, continued'))
  for (const t of kept) assert.ok(story.includes(t) || (continued && plain(continued).includes(t)), `the deck keeps "${t}"`)
  // The row gives the measure column to the kept split when it cannot hold both, as for the endpoint reconciliation.
  // The split carries the measure's figures either way.
  // The executive summary tier names the members evaluated.
  assert.ok(xmls.some(x => plain(x).includes('Evaluated members without MFA')), 'the hardening tier label')
  assert.ok(/Evaluated members on MFA at sign-in/.test(plain(pillarXml)) || story.includes('180 of them showed multifactor authentication'), story)
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
test('Defender for Identity as the only gap is defense in depth, so the posture slide reads no foundational gaps', async () => {
  // Defense in depth since Oct 16, 2026: it needs licensing and sensors from the client, so it sits in Later.
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
  assert.ok(/No foundational gaps\. Every measured foundational control reads E\./.test(posture), posture)
  assert.ok(!/licensing/.test(posture), 'no foundational control waits on licensing')
  assert.ok(slides.some(s => /Defender for Identity deployment/.test(s)), 'the Later item stays on the roadmap')
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
test('confirmed threats get their own slide at balanced and detailed depth, with the table only when there are examples', async () => {
  const isThreats = s => s.includes('Confirmed threats') && s.includes('Log4Shell')
  const has = async (depth, rows) => (await read(deck(depth, rows).out)).slides.some(isThreats)
  const { data, out } = deck('balanced', examples)
  const { slides, notes } = await read(out)
  const slide = slides.find(isThreats)
  assert.ok(slide, 'balanced has the slide')
  assert.equal(await has('detailed', examples), true)
  assert.equal(await has('brief', examples), false)
  const plain = (await read(deck('balanced').out)).slides
  assert.ok(!plain.some(s => /Attack stage/.test(s)), 'no examples, no table')
  assert.ok(/Command and control/.test(slide) && /August\u00A02026/.test(slide) && /July\u00A02026/.test(slide), 'stage and month, with the year bound to the month')
  const m = build(data)
  for (const n of [...m.presenter, ...m.review]) assert.ok(!notes.join(' ').includes(n.text), `speaker notes carry "${n.title}"`)
})
test('the more line counts the alerts and groups past the five examples', async () => {
  const group = (name, severity, n) => Array.from({ length: n }, (_, i) => ({ Threat: `${name} detected`, Severity: severity, Tactics: 'Execution', Created: `2026-08-1${i}`, ExfilOrImpactTactic: false }))
  const five = ['Alpha', 'Bravo', 'Charlie', 'Delta', 'Echo'].flatMap(n => group(n, 'High', 1))
  // Without a reviewed impact record the caption ends with the tactic reading and the request for more evidence.
  const caption = async rows => (await threatsSlide(deck('balanced', rows).out)).text.find(t => t.includes('grouped by alert title.'))
  assert.equal(await caption([...five, ...group('Foxtrot', 'Low', 2), ...group('Golf', 'Low', 1)]), `And 3 more confirmed alerts in 2 further groups. Classified as true positives by the SOC, grouped by alert title. ${GATE}`)
  assert.equal(await caption([...five, ...group('Foxtrot', 'Low', 1)]), `And 1 more confirmed alert in 1 further group. Classified as true positives by the SOC, grouped by alert title. ${GATE}`)
  assert.equal(await caption(five), `Classified as true positives by the SOC, grouped by alert title. ${GATE}`)
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
  assert.ok(/7 users\s+on text message or voice MFA ahead of Feb 1, 2027 \(Jul 1, 2027 for Global Administrators and external users\)/.test(summary), summary.match(/.{0,30}voice MFA.{0,80}/)?.[0])
  assert.ok(!/detections? correlated/.test(summary), 'the alert KPI no longer carries the detection count')
  assert.ok(/Alerts triaged Nov 1, 2025 to Sep 30, 2026/.test(summary), 'the alert KPI carries the period')
  assert.ok(/Median time to close, high severity alerts/.test(summary) && !/Confirmed threats with exfiltration/.test(summary))
  const m = build(p)
  assert.ok(summary.includes('Members without MFA') && summary.includes(`${m.tiers.hardening.find(r => r.id === 'IA.1').value}`), 'the hardening tier reads the MFA count against its population')
  assert.ok(slides.some(s => s.includes('Decisions needed') && /Grant read access/.test(s)), 'the closing slide still asks for read access')
  assert.ok(!/passwordless/i.test(slides.join(' ')), 'no passwordless wording anywhere in the deck')
})
test('a short confirmed threats table is followed by the outcome cards and the handling strip', async () => {
  const { data, out } = deck('balanced', examples)
  const { slides, notes } = await read(out)
  const slide = slides.find(s => s.startsWith('Confirmed threats') && s.includes('Log4Shell'))
  for (const t of ['Confirmed threats', 'Alerts the SOC classified as true positives from', 'Carried an exfiltration or impact tactic', 'A tactic Sentinel recorded on the alert, not a verified outcome.', '1 High severity alert', 'Of the 2 confirmed alerts grouped above, at the severity Sentinel recorded.', 'EVERY CONFIRMED THREAT', '1 Detect', '2 Triage', '3 Classify', 'the SOC records a true-positive classification on the alert', '4 Impact', 'confirmed only from reviewed investigation records', GATE]) assert.ok(slide.includes(t), t)
  // The strip and its note name only what the evidence records. A true positive is a classification with no status,
  // so no confirmed threat reads as investigated, assessed for impact or closed beside the caption that asks for
  // the investigation evidence.
  const strip = slide.slice(slide.indexOf('EVERY CONFIRMED THREAT'))
  const threatNotes = notes.find(n => n.includes('Every confirmed threat follows the same path'))
  assert.ok(threatNotes, 'the speaker notes describe the handling strip')
  assert.ok(!/\binvestigated?\b|\bassess|\bclosed\b|\bresolve/i.test(strip), strip)
  assert.ok(!/\binvestigated?\b|\bassess(es|ed)\b|closed by the SOC|closed with a documented disposition/i.test(threatNotes), threatNotes.match(/.{0,60}(investigat|assess|closed).{0,60}/i)?.[0])
  assert.ok(!/\bcontain(ed|ment)\b|resulted in|notification process/i.test(slide), 'containment, verified outcomes and notifications are never claimed')
  // A tactic recorded on the alert is never an outcome, and without a reviewed impact record no surface rules impact out.
  assert.ok(!/\breached\b|no impact|did not reach/i.test([...slides, ...notes].join(' ')), 'an outcome verb or an unrecorded impact determination reached the deck')
  assert.ok(!/investigated/i.test(slide + slides.find(s => s.startsWith('Executive summary'))), 'a true positive never reads as investigated')
  // The true positive count and the rows carry no status, so the cards never say the alerts were closed.
  const between = (a, b) => slide.slice(slide.indexOf(a), slide.indexOf(b))
  assert.ok(!/\bclosed\b/.test(between('Alerts the SOC classified', 'Carried an exfiltration or impact tactic')) && !/\bclosed\b/.test(between('High severity alert', 'Median time to close')), 'no true positive card claims closure')
  // One High and nine Low alerts under one title: the group reads High, the card counts one High alert of ten.
  const mixed = [{ Threat: 'Suspicious sign-in detected', Severity: 'High', Tactics: 'InitialAccess,Exfiltration', Created: '2026-08-01', ExfilOrImpactTactic: true }, ...Array.from({ length: 9 }, (_, i) => ({ Threat: 'Suspicious sign-in detected', Severity: 'Low', Tactics: 'InitialAccess', Created: `2026-08-0${i + 1}`, ExfilOrImpactTactic: false }))]
  const mixedSlide = (await read(deck('balanced', mixed).out)).slides.find(s => s.startsWith('Confirmed threats')).replace(/\u00A0/g, ' ')
  assert.ok(mixedSlide.includes('1 High severity alert') && mixedSlide.includes('Of the 10 confirmed alerts grouped above') && !mixedSlide.includes('10 High severity alerts'), mixedSlide.match(/.{0,20}High severity alert.{0,40}/)?.[0])
  assert.ok(mixedSlide.includes('1 of 3') && mixedSlide.includes('1 alert carried an exfiltration or impact tactic in Sentinel, not a verified outcome.'), 'a flagged alert reads as a tactic, not an outcome')
  assert.ok(mixedSlide.includes('Based on the tactics Sentinel recorded on the alerts, 1 of the 3 confirmed threats carried an exfiltration or impact tactic. Additional investigation evidence'), mixedSlide.match(/Based on.{0,120}/)?.[0])
  // Collection-only true positives: the collector flags them, but no tactic is Exfiltration or Impact, so the card reads none.
  const collection = Array.from({ length: 3 }, (_, i) => ({ Threat: 'Suspicious inbox rule created', Severity: 'High', Tactics: 'Collection', Created: `2026-08-0${i + 1}`, ExfilOrImpactTactic: true }))
  const collectionSlide = (await read(deck('balanced', collection).out)).slides.find(s => s.startsWith('Confirmed threats')).replace(/\u00A0/g, ' ')
  assert.ok(collectionSlide.includes('0 of 3') && collectionSlide.includes('Carried an exfiltration or impact tactic') && collectionSlide.includes('A tactic Sentinel recorded on the alert, not a verified outcome.'), collectionSlide.match(/.{0,10}of 3.{0,80}/)?.[0])
  // Rows without tactics (an older builder) keep the flag count and name the wider scope.
  const legacy = collection.map(({ Tactics, ...r }) => r)
  const legacyDeck = await read(deck('balanced', legacy).out)
  const legacySummary = legacyDeck.slides.find(s => s.startsWith('Executive summary')).replace(/\u00A0/g, ' ')
  assert.ok(legacySummary.includes('3 of 3') && legacySummary.includes('True positives whose alerts carried a collection, exfiltration or impact tactic') && legacySummary.includes('Collection, exfiltration or impact tactic'), legacySummary.match(/.{0,20}collection.{0,60}/i)?.[0])
  assert.ok(!legacyDeck.slides.some(s => /Attack stage/.test(s)), 'rows without tactics have no examples table')
  const m = build(data)
  for (const n of [...m.presenter, ...m.review]) assert.ok(!notes.join(' ').includes(n.text), `speaker notes carry "${n.title}"`)
})
test('a reviewed impact record in the context file is the only thing that prints an impact determination', async () => {
  const record = (confirmed, extra = {}) => ({ Confirmed: confirmed, Reviewed: '2026-10-10', Reference: 'CHG-123', WindowStart: '2025-11-01', WindowEnd: '2026-09-30', ...extra })
  const withContext = async (context, out1 = null, rows = examples) => {
    const p = pack('balanced', rows)
    p.context = context
    if (out1) p.results['OUT.1'] = [out1]
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ebr-deck-')), dataFile = path.join(dir, 'data.json'), out = path.join(dir, 'deck.pptx')
    fs.writeFileSync(dataFile, JSON.stringify(p))
    execFileSync(process.execPath, [path.join(__dirname, '..', 'report', 'build-report-deck.cjs'), dataFile, out])
    const { slides, notes } = await read(out)
    const plain = s => s.replace(/\u00A0/g, ' ')
    return { all: plain([...slides, ...notes].join(' ')), summary: plain(slides.find(s => s.startsWith('Executive summary'))), threats: plain(slides.find(s => s.startsWith('Confirmed threats'))) }
  }
  const none = await withContext({ ClientName: 'Example', TenantId: 't' })
  assert.ok(none.threats.includes(GATE) && !/Confirmed impact, reviewed/.test(none.summary), 'without a record the caption asks for more evidence and the summary has no impact row')
  assert.ok(!/\breached\b|no impact|did not reach|data exposure or business impact confirmed/i.test(none.all), none.all.match(/.{0,40}(reached|no impact|did not reach).{0,40}/i)?.[0])
  const clear = await withContext({ ClientName: 'Example', TenantId: 't', Impact: record(0) })
  assert.ok(clear.threats.includes('The reviewed investigation records confirm no data exposure or business impact from the 3 confirmed threats (CHG-123, reviewed Oct 10, 2026).') && !clear.threats.includes(GATE), clear.threats.match(/.{0,40}investigation records.{0,120}/)?.[0])
  assert.ok(/Confirmed impact, reviewed\s+0/.test(clear.summary) && /The reviewed investigation records confirm no data exposure or business impact\./.test(clear.summary), clear.summary.match(/.{0,60}impact.{0,60}/)?.[0])
  const hit = await withContext({ ClientName: 'Example', TenantId: 't', Impact: record(1) })
  assert.ok(hit.threats.includes('confirm data exposure or business impact from 1 of the 3 confirmed threats (CHG-123, reviewed Oct 10, 2026).'), 'a confirmed impact is stated, never softened')
  assert.ok(!/confirmed threats carried an exfiltration or impact tactic\s+All classified/.test(hit.summary), 'a confirmed impact withdraws the tactic win')
  const malformed = await withContext({ ClientName: 'Example', TenantId: 't', Impact: { Confirmed: 0 } })
  assert.ok(malformed.threats.includes(GATE), 'a record without a review date and reference prints nothing')
  // A context file reused from an earlier period is rejected, so its determination never covers later true positives.
  const stale = await withContext({ ClientName: 'Example', TenantId: 't', Impact: record(0, { Reviewed: '2026-06-30', Reference: 'Q2-review', WindowStart: '2026-04-01', WindowEnd: '2026-06-30' }) })
  assert.ok(stale.threats.includes(GATE) && !/investigation records confirm/.test(stale.all), 'a prior-period record prints nothing')
  // At the 90 percent closure boundary the resolved share earns a tier row, and the reviewed impact still sits in the
  // three rows the band shows.
  const boundary = await withContext({ ClientName: 'Example', TenantId: 't', Impact: record(1) }, { Raised: 100, Closed: 90, Open: 10, TruePositive: 3, ClosedUnclassified: 5 })
  assert.ok(/Confirmed impact, reviewed\s+1/.test(boundary.summary), boundary.summary.match(/TIER 1.{0,160}/)?.[0])
  // Every title withheld: the pack has true positives but no screened example, so the slide holds the cards and the
  // statement without the table, and never the withheld placeholder.
  const withheldRows = [{ Threat: 'Title withheld', Severity: 'High', Tactics: 'Exfiltration', Created: '2026-08-01', ExfilOrImpactTactic: true }, { Threat: 'Title withheld', Severity: 'Low', Tactics: 'InitialAccess', Created: '2026-08-02', ExfilOrImpactTactic: false }]
  const withheld = await withContext({ ClientName: 'Example', TenantId: 't' }, null, withheldRows)
  assert.ok(withheld.threats, 'the slide is built without examples')
  assert.ok(!/Attack stage|Title withheld|High severity alert/.test(withheld.threats), withheld.threats.slice(0, 200))
  for (const t of ['3 alerts the SOC classified as true positives from Nov 1, 2025 to Sep 30, 2026.', 'Based on the tactics Sentinel recorded on the alerts, 1 of the 3 confirmed threats carried an exfiltration or impact tactic. Additional investigation evidence is required', 'Carried an exfiltration or impact tactic', 'EVERY CONFIRMED THREAT']) assert.ok(withheld.threats.includes(t), t)
  const withheldClear = await withContext({ ClientName: 'Example', TenantId: 't', Impact: record(0) }, null, withheldRows)
  assert.ok(withheldClear.threats.includes('The reviewed investigation records confirm no data exposure or business impact from the 3 confirmed threats (CHG-123, reviewed Oct 10, 2026).'), 'the reviewed determination prints without examples too')
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
  const plain = slide.replace(/\u00A0/g, ' ')
  for (const t of ['days to move 7 users', 'when text message and voice sign-in retire for most users, and Jul 1, 2027 for Global Administrators and external users', 'USERS BY SIGN-IN METHOD, LAST 30 DAYS', 'Authenticator app or OTP token', 'Text message or voice', 'Notify the affected users', 'Register a phishing-resistant method', 'or Windows Hello for Business, in guided waves', 'Authenticator push stays supported', 'Remove the retiring methods', 'A telephony provider stays only for a documented regulatory or operational need', 'Confirm readiness early', 'Whether these users hold another registered MFA method is not yet evaluated.', 'OUTCOME']) assert.ok(plain.includes(t), t)
  assert.ok(!/Authenticator or OTP\b(?! token)|already sign in with Microsoft Authenticator|Register a stronger method/.test(plain), 'the bucket and the caption name what IA.2 counts')
  const note = notes[slides.indexOf(slide)].replace(/\u00A0/g, ' ')
  assert.ok(note.includes('Sign-in use alone does not show that a user has no other method.') && note.includes('From September 1, 2026, Microsoft enables passkeys') && note.includes('A user moved to a telephony provider from Microsoft Security Store before that date does not receive it.') && note.includes('a telephony provider from Microsoft Security Store is kept only for a documented regulatory or operational need'.replace(/^a/, 'A')), note)
  assert.ok(!slides.some(s => /Passwordless transition/.test(s)) && !/passwordless/i.test([...slides, ...notes].join(' ')))
})
test('every text box on the MFA method update slide holds its text, with and without the IA.5 registration count', async () => {
  for (const ia5 of [null, { Members: 1200, MfaRegistered: 1100, PhishingResistant: 25, PhoneRegistered: 900, AuthenticatorRegistered: 150, PhoneOnly: 1234 }]) {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ebr-deck-'))
    const data = pack('brief'), dataFile = path.join(dir, 'data.json'), out = path.join(dir, 'deck.pptx')
    data.results['IA.2'] = [{ Bucket: 'Retiring: SMS or voice', DistinctUsers: 1234 }, { Bucket: 'Authenticator or OTP', DistinctUsers: 18500 }, { Bucket: 'Phishing-resistant', DistinctUsers: 3 }]
    if (ia5) { data.manifest.push({ ResultId: 'IA.5', Status: 'OK', Rows: 1, ReadTimeUtc: '2026-10-08T10:00:00Z' }); data.results['IA.5'] = [ia5] }
    fs.writeFileSync(dataFile, JSON.stringify(data))
    execFileSync(process.execPath, [path.join(__dirname, '..', 'report', 'build-report-deck.cjs'), dataFile, out])
    const zip = await JSZip.loadAsync(fs.readFileSync(out))
    let xml = ''
    for (const n of Object.keys(zip.files).filter(n => /^ppt\/slides\/slide\d+\.xml$/.test(n))) { const x = await zip.file(n).async('string'); if (x.includes('>MFA method update<')) xml = x }
    assert.ok(xml, 'the slide is there')
    if (ia5) assert.ok(xml.includes('The registration read finds 1,234 members whose only registered MFA method is text message or voice.'))
    const shapes = [...xml.matchAll(/<p:sp>[\s\S]*?<\/p:sp>/g)].map(m => m[0]).filter(sp => /name="(Step \d+|Countdown label|Methods caption|Method \d+ label|Outcome)"/.test(sp))
    assert.equal(shapes.length, 10, 'four steps, the countdown label, the caption, three method labels and the outcome')
    for (const sp of shapes) {
      const name = sp.match(/name="([^"]+)"/)[1]
      const [, cx, cy] = sp.match(/<a:ext cx="(\d+)" cy="(\d+)"\/>/).map(Number)
      const paras = [...sp.matchAll(/<a:p>([\s\S]*?)<\/a:p>/g)].map(p => [...p[1].matchAll(/<a:r><a:rPr\b[^>]*\bsz="(\d+)"[^>]*?(\bb="1")?[^>]*>[\s\S]*?<a:t>([^<]*)<\/a:t>/g)].map(r => ({ size: Number(r[1]) / 100, bold: !!r[2] || /\bb="1"/.test(r[0]), text: r[3] }))).filter(p => p.length)
      // The outcome strip is one paragraph with a label run, measured at its body size.
      const need = paras.reduce((h, p, k) => h + (k ? 2 / 72 : 0) + lines(p.map(r => r.text).join(''), cx / 914400, Math.max(...p.map(r => r.size)), p.every(r => r.bold)) * Math.max(...p.map(r => r.size)) / 72 * 1.2, 0)
      assert.ok(need <= cy / 914400 + 0.01, `${name} needs ${need.toFixed(2)} in and holds ${(cy / 914400).toFixed(2)} in: ${paras.map(p => p.map(r => r.text).join('')).join(' | ')}`)
    }
  }
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
test('the time to close table shows every figure of the fixed cohort, with acknowledge beside close, and its caption fits above the next quadrant', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ebr-deck-'))
  const data = pack('balanced'), dataFile = path.join(dir, 'data.json'), out = path.join(dir, 'deck.pptx')
  data.results['OUT.2'] = [{ Scope: 'All', Incidents: 80, AutoClosed: 30, MedianTriageMin: 3, MedianCloseMin: 12, P90CloseMin: 300 }, { Scope: 'High', Incidents: 30, AutoClosed: 12, MedianTriageMin: 2, MedianCloseMin: 7, P90CloseMin: 95 }, { Scope: 'Medium', Incidents: 25, AutoClosed: 9, MedianTriageMin: 4, MedianCloseMin: 40, P90CloseMin: 400 }, { Scope: 'Low', Incidents: 25, AutoClosed: 9, MedianTriageMin: 5, MedianCloseMin: 60, P90CloseMin: 900 }]
  data.manifest.push({ ResultId: 'OUT.2-ANALYST', Status: 'OK', Rows: 1, ReadTimeUtc: '2026-10-08T10:00:00Z' })
  data.results['OUT.2-ANALYST'] = [{ Scope: 'High', Incidents: 18, AutoClosed: 0, MedianTriageMin: 9, MedianCloseMin: 45, P90CloseMin: 240 }]
  data.context = { ResponseTargetMinutes: 60 }
  fs.writeFileSync(dataFile, JSON.stringify(data))
  execFileSync(process.execPath, [path.join(__dirname, '..', 'report', 'build-report-deck.cjs'), dataFile, out])
  const zip = await JSZip.loadAsync(fs.readFileSync(out))
  const names = Object.keys(zip.files).filter(n => /^ppt\/slides\/slide\d+\.xml$/.test(n))
  const xmls = await Promise.all(names.map(n => zip.file(n).async('string')))
  const index = xmls.findIndex(x => x.includes('name="Time to close table"')), xml = xmls[index]
  assert.ok(xml, 'the operations slide has the table')
  const frame = xml.slice(xml.indexOf('name="Time to close table"'), xml.indexOf('</p:graphicFrame>', xml.indexOf('name="Time to close table"')))
  const [, tableY] = frame.match(/<a:off x="\d+" y="(\d+)"\/>/).map(Number)
  const rows = [...frame.matchAll(/<a:tr h="(\d+)"[^>]*>([\s\S]*?)<\/a:tr>/g)]
  const cells = rows.map(r => (r[2].match(/<a:t>[^<]*<\/a:t>/g) || []).map(t => t.slice(5, -6)).join(' | '))
  assert.equal(cells[0], 'Severity | Closed | Median to acknowledge | Median to close | 90% closed within')
  assert.equal(cells[1], 'High | 30 | 2 min | 7 min | 1.6 hr', 'a median under 20 minutes and a 90th percentile over one hour are both shown')
  assert.equal(cells[4], 'All closed | 80 | 3 min | 12 min | 5 hr', 'the all row includes automation closures')
  const caption = xml.match(/name="Time to close caption"[\s\S]*?<a:off x="\d+" y="(\d+)"\/><a:ext cx="\d+" cy="(\d+)"\/>[\s\S]*?<\/p:sp>/)
  const captionText = (caption[0].match(/<a:t>[^<]*<\/a:t>/g) || []).map(t => t.slice(5, -6)).join('')
  assert.equal(captionText, 'Acknowledge is the first status change from New. A median under 20 minutes or a 90th percentile over one hour is covered in the review.')
  const tableBottom = tableY + rows.reduce((n, r) => n + Number(r[1]), 0)
  assert.ok(tableBottom <= Number(caption[1]), 'the caption sits below the table')
  assert.ok(Number(caption[1]) + Number(caption[2]) <= 4.55 * EMU, `the caption ends at ${((Number(caption[1]) + Number(caption[2])) / EMU).toFixed(2)} in, past the next quadrant`)
  const notes = await zip.file(`ppt/notesSlides/notesSlide${names[index].match(/(\d+)\.xml$/)[1]}.xml`)?.async('string')
  const noteText = (notes.match(/<a:t>[^<]*<\/a:t>/g) || []).map(t => t.slice(5, -6)).join(' ')
  assert.ok(noteText.includes('Of the high severity alerts, 12 were closed by automation rules. Analyst-handled: median 45 min, 90th percentile 4 hr.'), noteText)
  assert.ok(noteText.includes('Against the agreed 1 hr response target, the median time to close of 7 min is under it and the 90th percentile of 1.6 hr is over it.'), noteText)
  assert.ok(noteText.includes('for every high severity alert created in the period and closed by collection') && !/closed in the period/.test(noteText), noteText)
  assert.ok(!/Medians under 20 minutes are not presented/.test(noteText))
})
test('the deck words planned work as a recommendation: the gaps panel, the roadmap notes and the MFA outcome strip', async () => {
  const { slides, notes } = await read(deck('balanced').out)
  const all = [...slides, ...notes].join(' ').replace(/ /g, ' ')
  assert.ok(all.includes('Below the baseline at collection. Atmosera recommends closing each gap first.'), 'the gaps panel recommends, never schedules')
  assert.ok(all.includes('Atmosera recommends staging each enforcement in an audit or report-only mode where the control supports one, reviewing it with your team, then turning it on.'))
  assert.ok(all.includes('Every affected user registered on a replacement method before February 1, 2027 (July 1, 2027 for Global Administrators and external users), the fallback tested, and no rise in failed sign-ins after enforcement.'), 'the outcome strip carries measurable criteria')
  assert.ok(all.includes('confirms each affected user holds a replacement method'))
  assert.ok(!/schedules each fix|non-event|No blocked sign-ins|no sign-in is blocked|Every enforcement is staged|Scoped and sequenced/i.test(all), all.match(/.{0,50}(schedules each fix|non-event|blocked sign-ins|sign-in is blocked|Every enforcement is staged|Scoped and sequenced).{0,50}/i)?.[0])
})
test('a reviewed status with a URL-length reference fits inside its decision card, and the notes keep the full attribution', async () => {
  const url = 'https://example.service-now.com/change_request.do?sys_id=0123456789abcdef0123456789abcdef'
  const build = actions => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ebr-deck-'))
    const data = pack('balanced'), dataFile = path.join(dir, 'data.json'), out = path.join(dir, 'deck.pptx')
    // Two more asks beside the MFA method update, so the cards sit two by two at their smallest.
    data.manifest.push({ ResultId: 'IA.11', Status: 'OK', Rows: 1, ReadTimeUtc: '2026-10-08T10:00:00Z' }, { ResultId: 'NB.1', Status: 'OK', Rows: 1, ReadTimeUtc: '2026-10-08T10:00:00Z' }, { ResultId: 'IA.13', Status: 'OK', Rows: 1, ReadTimeUtc: '2026-10-08T10:00:00Z' })
    Object.assign(data.results, { 'IA.11': [{ SignInRiskPolicies: 0, SignInRiskAllUsers: false, UserRiskPolicies: 0, UserRiskAllUsers: false, InForce: false }], 'NB.1': [{ WorkloadSubnets: 36, Segmented: 4 }], 'IA.13': [{ UserConsent: 'Allowed', AdminConsentWorkflow: false, Governed: false }] })
    data.context = { Actions: actions }
    fs.writeFileSync(dataFile, JSON.stringify(data))
    execFileSync(process.execPath, [path.join(__dirname, '..', 'report', 'build-report-deck.cjs'), dataFile, out])
    return out
  }
  const window = { Reviewed: '2026-10-16', WindowStart: '2025-11-01', WindowEnd: '2026-09-30' }
  const owner = 'Client identity and access management owner with the Atmosera service delivery manager'
  for (const actions of [[{ Key: 'methods', Status: 'AwaitingApproval', TargetDate: '2026-11-30', Reference: url, ...window }],
    [{ Key: 'methods', Status: 'PendingValidation', Owner: owner, TargetDate: '2026-11-30', Reference: url, ...window }, { Key: 'idp', Status: 'AwaitingApproval', Owner: owner, TargetDate: '2026-12-15', Reference: `${url}${url}`, ...window }]]) {
    const out = build(actions)
    const zip = await JSZip.loadAsync(fs.readFileSync(out))
    const names = Object.keys(zip.files).filter(n => /^ppt\/slides\/slide\d+\.xml$/.test(n))
    let xml = ''
    for (const n of names) { const x = await zip.file(n).async('string'); if (x.includes('>Decisions needed<')) xml = x }
    assert.ok(xml, 'the decisions slide is there')
    const shapes = [...xml.matchAll(/<p:sp>[\s\S]*?<\/p:sp>/g)].map(m => m[0])
    const asks = shapes.filter(sp => /name="Ask \d+"/.test(sp))
    assert.ok(asks.length >= 3, `${asks.length} asks`)
    for (const sp of asks) {
      const [, cx, cy] = sp.match(/<a:ext cx="(\d+)" cy="(\d+)"\/>/).map(Number)
      // Paragraphs and their runs at the size each was written in, measured the way the builder measures them.
      const paras = [...sp.matchAll(/<a:p>([\s\S]*?)<\/a:p>/g)].map(p => [...p[1].matchAll(/<a:r><a:rPr\b[^>]*\bsz="(\d+)"[^>]*?(\bb="1")?[^>]*>[\s\S]*?<a:t>([^<]*)<\/a:t>/g)].map(r => ({ size: Number(r[1]) / 100, bold: !!r[2] || /\bb="1"/.test(r[0]), text: r[3] }))).filter(p => p.length)
      const need = paras.reduce((h, p, k) => h + (k ? 4 / 72 : 0) + lines(p.map(r => r.text).join(''), cx / 914400, p[0].size, p[0].bold) * p[0].size / 72 * 1.2, 0)
      assert.ok(need <= cy / 914400 + 0.01, `${sp.match(/name="(Ask \d+)"/)[1]} needs ${need.toFixed(2)} in and holds ${(cy / 914400).toFixed(2)} in: ${paras.map(p => p.map(r => r.text).join('')).join(' | ')}`)
    }
    const status = asks.map(sp => [...sp.matchAll(/<a:t>([^<]*)<\/a:t>/g)].map(t => t[1]).join(' ')).join(' ')
    assert.ok(/(Awaiting approval|Pending validation)/.test(status), 'the status shows on the card')
    assert.ok(!status.includes('…'), 'cut with three dots, never the ellipsis glyph')
    const { notes } = await read(out)
    assert.ok(notes.join(' ').includes(`${url},`), 'the speaker notes keep the full reference')
  }
})
test('a reviewed drift status with a URL-length reference stays above the first foundational gap, and the notes keep it in full', async () => {
  const url = 'https://example.service-now.com/change_request.do?sys_id=0123456789abcdef0123456789abcdef'
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ebr-deck-'))
  const data = pack('balanced'), dataFile = path.join(dir, 'data.json'), out = path.join(dir, 'deck.pptx')
  data.context = { Actions: [{ Key: 'drift', Status: 'Scheduled', TargetDate: '2026-11-30', Reference: url, Reviewed: '2026-10-16', WindowStart: '2025-11-01', WindowEnd: '2026-09-30' }] }
  fs.writeFileSync(dataFile, JSON.stringify(data))
  execFileSync(process.execPath, [path.join(__dirname, '..', 'report', 'build-report-deck.cjs'), dataFile, out])
  const zip = await JSZip.loadAsync(fs.readFileSync(out))
  let xml = ''
  for (const n of Object.keys(zip.files).filter(n => /^ppt\/slides\/slide\d+\.xml$/.test(n))) { const x = await zip.file(n).async('string'); if (x.includes('name="Drift heading"')) xml = x }
  assert.ok(xml, 'the control posture slide has the gaps panel')
  const shape = name => [...xml.matchAll(/<p:(?:sp|cxnSp)>[\s\S]*?<\/p:(?:sp|cxnSp)>/g)].map(m => m[0]).find(sp => sp.includes(`name="${name}"`))
  const box = sp => { const [, x, y, cx, cy] = sp.match(/<a:off x="(\d+)" y="(\d+)"\/><a:ext cx="(\d+)" cy="(\d+)"\/>/).map(Number); return { x: x / 914400, y: y / 914400, w: cx / 914400, h: cy / 914400 } }
  const head = shape('Drift heading'), rule1 = shape('Drift 1 rule')
  assert.ok(head && rule1, 'the heading and the first gap are drawn')
  const note = [...head.matchAll(/<a:t>([^<]*)<\/a:t>/g)].map(t => t[1]).slice(1).join('')
  assert.match(note, /^Below the baseline at collection\. Fixes scheduled \(https:\/\/\S+\.\.\.\)\.$/)
  const end = box(head).y + 18 / 72 * 1.2 + 4 / 72 + lines(note, box(head).w, 12) * 12 / 72 * 1.2
  assert.ok(end <= box(rule1).y + 0.005, `the note ends at ${end.toFixed(2)} in, below the first gap's rule at ${box(rule1).y.toFixed(2)} in`)
  const { notes } = await read(out)
  assert.ok(notes.join(' ').includes(`Foundational fixes: scheduled, from the reviewed action record ${url}, reviewed Oct 16, 2026.`))
})
test('the posture appendix prints the model of each score, the score controls carry their healthy resources and the notes drop the all-or-nothing claim', async () => {
  const p = pack('detailed')
  const put = (id, rows) => { p.manifest.push({ ResultId: id, Status: 'OK', Rows: rows.length, ReadTimeUtc: '2026-10-08T10:00:00Z' }); p.results[id] = rows }
  put('POS.6', [{ ReadDate: '2026-10-10', Current: 412.5, Max: 1000, Percent: 41.25, IdentityPct: 50, DevicePct: 61, AppsPct: 59, DataPct: 71 }])
  put('POS.2', [{ AssessedResources: 12345 }])
  put('POS.7', [{ Month: '2026-07-01', Current: 18, Max: 40, Percent: 45 }, { Month: '2026-10-01', Current: 20, Max: 40, Percent: 50 }])
  p.results['POS.1'][0].Subscriptions = 12
  // A two-line movement and a two-line model line are the tallest tenant text.
  put('POS.6-TREND', [{ Date: '2026-07-15', Current: 300.5, Max: 1000, Percent: 30.05 }, { Date: '2026-10-10', Current: 412.5, Max: 1000, Percent: 41.25 }])
  put('POS.3', [{ Control: 'Remediate vulnerabilities', Current: 0.31, Max: 6, Healthy: 4, Unhealthy: 74 }, { Control: 'Apply system updates', Current: 2, Max: 6 }])
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ebr-deck-')), dataFile = path.join(dir, 'data.json'), out = path.join(dir, 'deck.pptx')
  fs.writeFileSync(dataFile, JSON.stringify(p))
  execFileSync(process.execPath, [path.join(__dirname, '..', 'report', 'build-report-deck.cjs'), dataFile, out])
  const { slides, notes } = await read(out)
  const posture = slides.find(s => s.startsWith('Tenant and cloud security posture')).replace(/ /g, ' ')
  assert.ok(posture.includes('Classic Defender for Cloud secure score across 12 subscriptions. Read Oct 8, 2026 from Azure Resource Graph.') && posture.includes('12,345 Resources assessed by Defender for Cloud'), posture)
  assert.ok(posture.includes('MICROSOFT SECURE SCORE · MICROSOFT 365 TENANT') && posture.includes('Microsoft Secure Score. Read Oct 10, 2026 from Microsoft Graph.') && posture.includes('Up 11.2 points since Jul 2026, from 30.1%.'), posture)
  // Both score texts hold in their boxes, and the tenant text ends above the first category bar.
  const zipped = await JSZip.loadAsync(fs.readFileSync(out))
  let xml = ''
  for (const n of Object.keys(zipped.files).filter(n => /^ppt\/slides\/slide\d+\.xml$/.test(n))) { const x = await zipped.file(n).async('string'); if (x.includes('name="Secure Score text"')) xml = x }
  const firstCategory = Number(xml.match(/name="Category 1 label"[\s\S]*?<a:off x="\d+" y="(\d+)"\/>/)[1]) / EMU
  for (const [name, room] of [['Defender for Cloud text', null], ['Secure Score text', firstCategory - 1.75 - 0.6]]) {
    const sp = xml.match(new RegExp(`<p:sp>(?:(?!</p:sp>)[\\s\\S])*name="${name}"[\\s\\S]*?</p:sp>`))[0]
    const [, cx, cy] = sp.match(/<a:ext cx="(\d+)" cy="(\d+)"\/>/).map(Number)
    const paras = [...sp.matchAll(/<a:p>([\s\S]*?)<\/a:p>/g)].map(q => [...q[1].matchAll(/<a:r><a:rPr\b[^>]*\bsz="(\d+)"[^>]*?(\bb="1")?[^>]*>[\s\S]*?<a:t>([^<]*)<\/a:t>/g)].map(r => ({ size: Number(r[1]) / 100, bold: !!r[2] || /\bb="1"/.test(r[0]), text: r[3] }))).filter(q => q.length)
    const need = paras.reduce((h, q, k) => h + (k ? 4 / 72 : 0) + lines(q.map(r => r.text).join(''), cx / EMU, Math.max(...q.map(r => r.size)), q.every(r => r.bold)) * Math.max(...q.map(r => r.size)) / 72 * 1.2, 0)
    assert.ok(need <= (room ?? cy / EMU) + 0.01, `${name} needs ${need.toFixed(2)} in and holds ${(room ?? cy / EMU).toFixed(2)} in`)
  }
  assert.ok(!notes.some(n => /all or nothing|no visible movement until a control completes/.test(n)), 'the all-or-nothing claim is gone from the notes')
  assert.ok(notes.some(n => n.includes('Within each subscription, a control earns points for every healthy resource it assesses, its maximum divided by its healthy and unhealthy resources in that subscription, so points can be gained before a control completes. The points and resource counts shown for each control are added across subscriptions')))
  const zip = await JSZip.loadAsync(fs.readFileSync(out))
  const charts = await Promise.all(Object.keys(zip.files).filter(n => /^ppt\/charts\/chart\d+\.xml$/.test(n)).map(n => zip.file(n).async('string')))
  const bar = charts.find(c => c.includes('Remediate vulnerabilities'))
  assert.ok(bar.includes('Remediate vulnerabilities (5.7 pts, 4 of 78 healthy)'), bar.match(/Remediate[^<]*/)?.[0])
  assert.ok(bar.includes('Apply system updates (4 pts)'), 'a control without resource counts carries none')
})
// The deck states the Defender XDR scope on the client surfaces: the A4 Alerts fact and the operations slide's
// speaker notes, which carry only page copy. The A4 Detections fact names only the sources OUT.5 holds (issue #22).
test('the scope appendix and the operations notes state the Defender XDR scope and name the detection sources OUT.5 holds', async () => {
  const plain = s => s.replace(/\s+/g, ' ')
  const EXCLUDED = 'Alerts investigated only in other platforms, including Microsoft Defender XDR, are not included. No Defender XDR alert was found in Sentinel in the year before collection.'
  const UNKNOWN = 'Alerts investigated only in other platforms, including Microsoft Defender XDR, may not be included. Whether Defender XDR alerts reach Sentinel was not read in this collection.'
  const surfaces = async data => {
    const { slides, notes } = await read(deckOf(data))
    const ops = slides.findIndex(s => /HOW CLOSED ALERTS WERE CLASSIFIED/i.test(s))
    assert.ok(ops >= 0, 'the operations slide')
    return { scope: plain(slides.find(s => s.startsWith('Scope and evidence')) || ''), notes: plain(notes[ops]), all: [...slides, ...notes].map(plain).join(' ') }
  }
  const data = pack('balanced')
  data.results['P0.1-XDRDUP'] = [{ XdrIncidents: 0, InMultipleWorkspaces: 0 }]
  data.results['OUT.5'] = [{ ProductName: 'Azure Sentinel', Alerts: 40 }, { ProductName: 'Azure Security Center', Alerts: 5 }]
  let s = await surfaces(data)
  assert.ok(s.scope.includes(`Alerts Sentinel records triaged by the managed security service. ${EXCLUDED}`), s.scope)
  assert.ok(s.scope.includes('Detections Records from Sentinel and Defender for Cloud correlated into those alerts.'), s.scope)
  assert.ok(s.notes.startsWith(`Detections from Sentinel and Defender for Cloud are correlated into alerts. ${EXCLUDED} Closed alerts:`), s.notes)
  assert.ok(!/Defender services/.test(s.all), 'no fixed source list remains')
  // A count above zero keeps a qualified statement. A missing reading says it was not read and never that Defender XDR alerts are in.
  data.results['P0.1-XDRDUP'] = [{ XdrIncidents: 20, InMultipleWorkspaces: 0 }]
  s = await surfaces(data)
  const REACHED = 'Alerts investigated only in other platforms, including the Microsoft Defender XDR portal, are not included. Defender XDR alerts are counted where Sentinel received them.'
  assert.ok(s.scope.includes(`Sentinel records triaged by the managed security service. ${REACHED}`) && s.notes.includes(REACHED), s.scope)
  data.manifest = data.manifest.filter(r => r.ResultId !== 'P0.1-XDRDUP'); delete data.results['P0.1-XDRDUP']
  s = await surfaces(data)
  assert.ok(s.scope.includes(`Sentinel records triaged by the managed security service. ${UNKNOWN}`) && s.notes.includes(UNKNOWN), s.scope)
  // Records without a product name are counted and never read as no records, and a zero total says there were none.
  data.results['OUT.5'] = [{ ProductName: '', Alerts: 5 }]
  s = await surfaces(data)
  assert.ok(s.scope.includes('Detections Records from sources not named in the collection correlated into those alerts.') && !s.scope.includes('No detection records'), s.scope)
  assert.ok(s.notes.startsWith('Detections from sources not named in the collection are correlated into alerts.'), s.notes)
  data.results['OUT.5'] = [{ ProductName: 'Azure Sentinel', Alerts: 0 }]
  s = await surfaces(data)
  assert.ok(s.scope.includes('Detections No detection records were correlated into those alerts.'), s.scope)
  // Without a detection reading no source is named.
  data.manifest = data.manifest.filter(r => r.ResultId !== 'OUT.5'); delete data.results['OUT.5']
  s = await surfaces(data)
  assert.ok(s.scope.includes('Detections Records correlated into those alerts. Detection sources are confirmed in the review.'), s.scope)
  assert.ok(s.notes.startsWith('Detections are correlated into alerts.'), s.notes)
})
// The scope facts step down in size so the longest Alerts fact, ticketed with the Defender XDR sentence, still ends
// above the content bottom. At 11 pt it ran past the foot of the slide.
test('the scope appendix facts end above the content bottom with the Defender XDR sentence on a ticketed pack', async () => {
  for (const xdr of [[{ XdrIncidents: 0, InMultipleWorkspaces: 0 }], [{ XdrIncidents: 20, InMultipleWorkspaces: 0 }], null]) {
    const data = pack('balanced')
    data.parameters.TicketPattern = 'ZD\\d+'
    if (xdr) data.results['P0.1-XDRDUP'] = xdr
    else { data.manifest = data.manifest.filter(r => r.ResultId !== 'P0.1-XDRDUP'); delete data.results['P0.1-XDRDUP'] }
    const zip = await JSZip.loadAsync(fs.readFileSync(deckOf(data)))
    const xml = (await Promise.all(Object.keys(zip.files).filter(n => /^ppt\/slides\/slide\d+\.xml$/.test(n)).map(n => zip.file(n).async('string')))).find(x => x.includes('name="Scope 1 value"'))
    assert.ok(xml && xml.includes('Defender XDR'), 'the scope slide carries the Defender XDR sentence')
    const facts = [...xml.matchAll(/<p:cNvPr id="\d+" name="(Scope \d+ (?:label|value|rule))"(?:(?!<p:cNvPr)[\s\S])*?<a:off x="\d+" y="(\d+)"\/><a:ext cx="\d+" cy="(\d+)"\/>/g)]
    assert.equal(facts.length, 27, 'a label, value and rule for each of the nine facts')
    for (const [, name, y, h] of facts) assert.ok(Number(y) + Number(h) <= BOTTOM_EMU + 1, `"${name}" ends at ${((Number(y) + Number(h)) / EMU).toFixed(3)} in, past the content bottom`)
  }
})

// The alert volume quadrant carries the workspace coverage line under the chart when the count varies across the
// months shown (issue #23), inside the quadrant and above the second row, and says it in the speaker notes.
test('the alert volume chart carries the workspace coverage line when it varies, and fits its quadrant', async () => {
  const withReach = reach => {
    const data = pack('balanced')
    data.parameters.Workspaces.push({ Name: 'w2', CustomerId: 'w2', RetentionDays: 365 })
    data.manifest.push({ ResultId: 'P0.1-BY-WORKSPACE', Status: 'OK', Rows: reach.length, ReadTimeUtc: '2026-10-08T10:00:00Z' })
    data.results['P0.1-BY-WORKSPACE'] = reach
    return data
  }
  const full = { WorkspaceId: 'w1', SourceTable: 'SecurityIncident', EarliestRecord: '2025-10-01', LatestRecord: '2026-10-07', Records: 400 }
  const plain = s => s.replace(/\u00A0/g, ' ')
  const opsXml = async out => {
    const zip = await JSZip.loadAsync(fs.readFileSync(out))
    const xmls = await Promise.all(Object.keys(zip.files).filter(n => /^ppt\/slides\/slide\d+\.xml$/.test(n)).map(n => zip.file(n).async('string')))
    return xmls.find(x => x.includes('name="Monthly alerts chart"'))
  }
  const box = (xml, name) => { const r = xml.match(new RegExp(`name="${name}"[\\s\\S]*?<a:off x="(\\d+)" y="(\\d+)"/><a:ext cx="(\\d+)" cy="(\\d+)"/>`)); return r && { y: Number(r[2]), h: Number(r[4]), bottom: Number(r[2]) + Number(r[4]) } }
  const lateData = withReach([full, { WorkspaceId: 'w2', SourceTable: 'SecurityIncident', EarliestRecord: '2026-08-12', LatestRecord: '2026-10-07', Records: 30 }])
  const m = build(lateData)
  const line = `${m.trendCoverage.sentence} ${m.trendCoverage.caption}`
  assert.equal(m.trendCoverage.caption, 'Workspaces whose retained alert records span the whole month: 1 of 2 in Aug 2026, 2 of 2 in Sep 2026.')
  const late = deckOf(lateData), { slides, notes } = await read(late)
  assert.ok(slides.some(s => plain(s).includes(line)), 'the operations slide shows the coverage line')
  assert.ok(notes.some(n => plain(n).includes(`${line} Evidence P0.1-BY-WORKSPACE. Read Oct 8, 2026.`)), 'the speaker notes carry it with its reach source')
  const xml = await opsXml(late), cap = box(xml, 'Monthly alerts coverage'), chart = box(xml, 'Monthly alerts chart')
  assert.ok(chart.bottom <= cap.y, 'the chart ends above the coverage line')
  assert.ok(cap.bottom <= Math.round(4.3 * EMU), `the coverage line ends at ${(cap.bottom / EMU).toFixed(2)} in, inside the quadrant`)
  assert.ok(cap.h >= Math.round((lines(line.replace(/(\d) of (\d)/g, '$1\u00A0of\u00A0$2').replace(/(Jul|Aug|Sep) (\d{4})/g, '$1\u00A0$2'), (require('../report/deck-common.cjs').CW - 0.5) / 2 - 0.1, 10) * 0.17) * EMU), 'the box holds every wrapped line')
  // With the count steady, no line and the chart keeps the full quadrant.
  const steady = deckOf(withReach([full, { ...full, WorkspaceId: 'w2' }]))
  const steadyXml = await opsXml(steady)
  assert.equal(box(steadyXml, 'Monthly alerts coverage'), null)
  assert.ok(box(steadyXml, 'Monthly alerts chart').h > chart.h)
  assert.ok(!(await read(steady)).notes.some(n => n.includes('span the whole month')))
  // The densest caption: twelve months shown and a workspace whose records start in each, so twelve separate runs.
  const months = Array.from({ length: 12 }, (_, i) => new Date(Date.UTC(2025, 9 + i, 1)).toISOString().slice(0, 10))
  const dense = withReach([])
  dense.parameters.WindowStart = '2025-10-01'
  dense.parameters.Workspaces = months.map((_, i) => ({ Name: `w${i}`, CustomerId: `w${i}`, RetentionDays: 365 }))
  dense.results['P0.1-BY-WORKSPACE'] = months.map((Month, i) => ({ ...full, WorkspaceId: `w${i}`, EarliestRecord: Month }))
  dense.manifest.find(r => r.ResultId === 'P0.1-BY-WORKSPACE').Rows = 12
  dense.results['OUT.3'] = months.map((Month, i) => ({ Month, Total: 20 + i, High: 2, Medium: 8, Low: 10 + i, Informational: 0 }))
  const dm = build(dense)
  assert.equal(dm.trendCoverage.caption.split(' in ').length - 1, 12, dm.trendCoverage.caption)
  const denseXml = await opsXml(deckOf(dense)), dcap = box(denseXml, 'Monthly alerts coverage'), dchart = box(denseXml, 'Monthly alerts chart')
  const dline = `${dm.trendCoverage.sentence} ${dm.trendCoverage.caption}`.replace(/(\d) of (\d)/g, '$1\u00A0of\u00A0$2').replace(/([A-Z][a-z]{2}) (\d{4})/g, '$1\u00A0$2')
  assert.ok(dchart.bottom <= dcap.y && dcap.bottom <= Math.round(4.3 * EMU), 'the dense line sits under the chart, inside the quadrant')
  assert.ok(dcap.h >= Math.round(lines(dline, (require('../report/deck-common.cjs').CW - 0.5) / 2 - 0.1, 10) * 0.17 * EMU), 'the box holds every wrapped line')
  assert.ok(dchart.h >= Math.round(0.9 * EMU), `the chart keeps ${(dchart.h / EMU).toFixed(2)} in`)
})
test('workload protection reads as a plan-level estimate and subnets as configured on every slide and note (issue #26)', async () => {
  const p = pack('detailed')
  p.manifest.push({ ResultId: 'DR.2', Status: 'OK', Rows: 1, ReadTimeUtc: '2026-10-08T10:00:00Z' }, { ResultId: 'NB.1', Status: 'OK', Rows: 1, ReadTimeUtc: '2026-10-08T10:00:00Z' })
  Object.assign(p.results, { 'DR.2': [{ Plan: 'VirtualMachines', ResourceType: 'microsoft.compute/virtualmachines', Resources: 40, Covered: 35 }], 'NB.1': [{ WorkloadSubnets: 30, Segmented: 20 }] })
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ebr-deck-')), dataFile = path.join(dir, 'data.json'), out = path.join(dir, 'deck.pptx')
  fs.writeFileSync(dataFile, JSON.stringify(p))
  execFileSync(process.execPath, [path.join(__dirname, '..', 'report', 'build-report-deck.cjs'), dataFile, out])
  const { slides, notes } = await read(out)
  const all = [...slides, ...notes]
  assert.ok(slides.some(t => t.includes('Cloud workload protection plan coverage, a plan-level estimate')), 'the register row names the estimate')
  assert.ok(notes.some(t => /Standard workload protection plans cover an estimated 87\.5% of eligible resources, a plan-level estimate/.test(t)), 'the pillar narrative names the estimate')
  for (const t of all) for (const hit of t.match(/[^.]*[Ww]orkload protection (plans )?covers?[^.]*/g) || []) assert.match(hit, /estimate/, hit)
  assert.ok(!all.some(t => /subnets segmented|Segmentation covers|Workload subnets protected|scanning on mail|across the resource estate/.test(t)), 'no outcome wording for configuration presence')
})
test('the controls standard cards for the configuration-presence controls hold their label and note (issue #26)', async () => {
  // The builder sizes every card on a page to the fullest one, capped by the space on the slide, so a note that
  // outgrows the cap runs past its card. The same estimate the builder uses must fit the text box it was given.
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ebr-standard-')), out = path.join(dir, 'standard.pptx')
  execFileSync(process.execPath, [path.join(__dirname, '..', 'report', 'build-controls-deck.cjs'), out])
  const zip = await JSZip.loadAsync(fs.readFileSync(out))
  const xml = (await Promise.all(Object.keys(zip.files).filter(n => /^ppt\/slides\/slide\d+\.xml$/.test(n)).map(n => zip.file(n).async('string')))).join('\n')
  const m = build({ parameters: { ClientName: 'MXDR controls standard' }, manifest: [], results: {}, standard: true })
  const EMU = 914400
  const ids = ['NB.1', 'DR.2', 'DP.3', 'IA.9-SAFELINKS', 'IA.9-SAFEATTACH']
  for (const id of ids) {
    const c = m.controls.find(x => x.source.includes(id) && (id !== 'NB.1' || /^Workload subnets/.test(x.label)) && (id !== 'DR.2' || /^Cloud workload/.test(x.label)))
    assert.ok(c, id)
    const name = c.label.replace(/&/g, '&amp;')
    const box = [...xml.matchAll(/name="[A-Z]\d+ ([^"]+)"[\s\S]*?<a:ext cx="(\d+)" cy="(\d+)"\/>/g)].find(x => x[1] === name)
    assert.ok(box, `${c.label} has a card`)
    const w = Number(box[2]) / EMU, h = Number(box[3]) / EMU
    const textH = lines(c.label, w, 14, true) * 0.245 + 0.08 + lines(c.note, w, 12) * 0.2
    assert.ok(textH + 0.1 <= h + 1e-6, `${c.label}: needs ${textH.toFixed(2)} in, card text box ${h.toFixed(2)} in`)
  }
})
