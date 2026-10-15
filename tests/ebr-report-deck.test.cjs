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
test('the grounding slides appear at balanced depth and carry the pillar narratives, the priority workstreams and the scope', async () => {
  const { data, out } = deck('balanced', examples)
  const m = build(data)
  const { slides, notes } = await read(out)
  // Figures and dates are glued with non-breaking spaces on the slide, so the comparison reads them as spaces.
  const plain = s => s.replace(/\u00A0/g, ' ')
  const pillars = plain(slides.find(s => s.startsWith('Measured outcomes by pillar')) || '')
  assert.ok(pillars, 'the pillar outcomes slide')
  for (const p of m.pillars) assert.ok(pillars.includes(p.name) && pillars.includes(p.headline), p.name)
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
  for (const [label, count] of [['Azure virtual machines reporting to endpoint detection', '1 exception'], ['Analytics rules enabled in Sentinel', '7 exceptions'], ['Key Vault soft delete', '1 exception'], ['Multifactor authentication required at sign-in', '14 exceptions']]) {
    assert.match(text, new RegExp(`${label}\\s+· ${count}\\b`), `${label} carries ${count}`)
  }
  // Every row ends inside the column the register sizes for.
  for (const xml of xmls) for (const r of xml.matchAll(/name="([^"]*) register rule"[\s\S]*?<a:off x="\d+" y="(\d+)"\/>/g)) assert.ok(Number(r[2]) <= 7.2 * EMU, `"${r[1]}" ends at ${(Number(r[2]) / EMU).toFixed(2)} in`)
  const { notes } = await read(out)
  assert.ok(notes.some(n => n.includes('Azure virtual machines reporting to endpoint detection: 88 of 89, 1 exception.')), 'the speaker notes say the count')
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
