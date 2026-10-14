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
  assert.ok(m.presenter.some(n => n.title === 'Foundational drift'), 'the fixture raises a presenter note')
  const { slides, notes } = await read(out)
  const all = slides.join(' ')
  assert.ok(all.includes('Multi-stage alert involving Initial access and Execution on one endpoint'), 'the incident title reads as an alert')
  assert.ok(!/;|→|←|object Object|\(null\)|\bincidents?\b/i.test(all.replace(/&[a-z]+;|&#\d+;/g, '')), all.match(/.{0,40}(;|object Object|\(null\)|incident).{0,40}/i)?.[0])
  assert.ok(!/\bNaN\b|\bundefined\b/.test(all), 'a missing value reached the slides')
  assert.ok(all.includes('Example'))
  const spoken = notes.join(' ')
  for (const n of [...m.presenter, ...m.review]) assert.ok(!spoken.includes(n.text), `speaker notes carry the presenter note "${n.title}"`)
  assert.ok(!/Foundational drift|foundational controls? reads? below E:|Prepared answers|Evidence review/.test(spoken))
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
  const { tableY, tableH, captionY, captionH, body, text } = await threatsSlide(deck('balanced', long).out)
  assert.ok(tableY + tableH <= captionY, 'the caption sits below the table')
  assert.ok(captionY + captionH <= BOTTOM_EMU, `the caption ends at ${((captionY + captionH) / EMU).toFixed(2)} in, past BOTTOM`)
  for (const row of body) assert.deepEqual([...new Set(row.match(/<a:rPr\b[^>]*\bsz="(\d+)"/g).map(r => r.match(/sz="(\d+)"/)[1]))], ['1200'], 'body runs at 12 pt')
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
