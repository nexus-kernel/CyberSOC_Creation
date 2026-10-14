/* Shared PowerPoint building blocks for the EBR decks: the Atmosera theme, the three layouts
   (title, content, closing), small drawing helpers and the theme writer. Used by
   build-report-deck.cjs and build-controls-deck.cjs so both decks look the same. */
'use strict'
const fs = require('node:fs')
const path = require('node:path')

function resolve(name, from) {
  // pptxgenjs from the usual places, then the runtime the headless checks already use. jszip ships
  // with pptxgenjs, so it is looked up beside it.
  const fallback = '/Users/nexus/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules'
  for (const paths of [from ? [from] : undefined, [fallback]]) {
    try { return require.resolve(name, paths ? { paths } : undefined) } catch { /* try the next place */ }
  }
  throw new Error(`${name} is not installed. Run npm install pptxgenjs, or set NODE_PATH to a node_modules folder that has it.`)
}
const pptxPath = resolve('pptxgenjs')
const PptxGenJS = require(pptxPath)
const JSZip = require(resolve('jszip', path.dirname(pptxPath)))

// Atmosera palette, from report.css.
const THEME = {
  name: 'Atmosera MXDR',
  headFontFace: 'Arial',
  bodyFontFace: 'Arial',
  colors: {
    dk1: '21374C', lt1: 'FFFFFF', dk2: '15365F', lt2: 'F3F6FA',
    accent1: '01ACD9', accent2: '007CB3', accent3: '1F9D74', accent4: 'F37321', accent5: '2E5B8C', accent6: '5A6B7F',
    hlink: '007CB3', folHlink: '2E5B8C'
  }
}
// Hex-only chart options cannot take scheme colors, so these mirror the theme.
const HEX = { ...THEME.colors, track: 'D8E1EC', sevHigh: '15365F', sevMedium: '2E5B8C', sevLow: '6D9AC2', sevInfo: 'BFD0E2' }

const W = 13.333, H = 7.5, X0 = 0.6, CW = W - 2 * X0
const asset = name => path.join(__dirname, 'assets', name)

function createDeck({ title, author = 'Atmosera' }) {
  const pres = new PptxGenJS()
  pres.layout = 'LAYOUT_WIDE'
  pres.theme = { headFontFace: THEME.headFontFace, bodyFontFace: THEME.bodyFontFace }
  pres.title = title
  pres.author = author
  pres.company = 'Atmosera'
  const C = pres.SchemeColor
  const wordmark = { text: { text: 'atmosera.', options: { x: 0.7, y: 6.55, w: 3, h: 0.5, fontSize: 28, bold: true, color: C.accent1, margin: 0 } } }
  const ph = (name, type, o) => ({ placeholder: { options: { name, type, margin: 0, align: 'left', ...o }, text: '' } })

  pres.defineSlideMaster({
    title: 'Atmosera Title',
    background: { path: asset('deck-title.jpg') },
    objects: [
      ph('eyebrow', 'body', { x: 0.7, y: 1.0, w: 8.6, h: 0.4, fontSize: 13, bold: true, color: C.accent1, charSpacing: 2 }),
      ph('title', 'title', { x: 0.7, y: 1.45, w: 8.0, h: 1.9, fontSize: 54, bold: true, color: C.background1, valign: 'top' }),
      ph('subtitle', 'body', { x: 0.7, y: 3.55, w: 8.6, h: 0.55, fontSize: 26, bold: true, color: C.background1 }),
      ph('caption', 'body', { x: 0.7, y: 4.2, w: 7.4, h: 0.85, fontSize: 18, color: C.background2, valign: 'top' }),
      ph('meta', 'body', { x: 0.7, y: 5.25, w: 8.6, h: 0.65, fontSize: 14, color: C.accent1, valign: 'top' }),
      wordmark
    ]
  })
  pres.defineSlideMaster({
    title: 'Atmosera Content',
    background: { color: C.background1 },
    objects: [
      { image: { x: 0, y: 0, w: W, h: 1.4, path: asset('deck-band.jpg') } },
      ph('title', 'title', { x: X0, y: 0.2, w: CW, h: 0.65, fontSize: 32, bold: true, color: C.background1, valign: 'middle' }),
      ph('subtitle', 'body', { x: X0, y: 0.85, w: CW, h: 0.4, fontSize: 16, color: C.background2, valign: 'middle' })
    ]
  })
  pres.defineSlideMaster({
    title: 'Atmosera Closing',
    background: { path: asset('deck-title.jpg') },
    objects: [
      ph('title', 'title', { x: 0.7, y: 2.3, w: 7.6, h: 1.0, fontSize: 44, bold: true, color: C.background1, valign: 'top' }),
      ph('body', 'body', { x: 0.7, y: 3.45, w: 7.0, h: 1.6, fontSize: 20, color: C.background2, valign: 'top' }),
      wordmark
    ]
  })

  // Eyebrow, title and takeaway over the space image, for the closing decisions slide.
  pres.defineSlideMaster({
    title: 'Atmosera Decisions',
    background: { path: asset('deck-title.jpg') },
    objects: [
      ph('eyebrow', 'body', { x: 0.7, y: 0.6, w: 9.6, h: 0.35, fontSize: 13, bold: true, color: C.accent1, charSpacing: 2 }),
      ph('title', 'title', { x: 0.7, y: 0.95, w: 9.6, h: 0.85, fontSize: 40, bold: true, color: C.background1, valign: 'top' }),
      ph('subtitle', 'body', { x: 0.7, y: 1.8, w: 9.6, h: 0.45, fontSize: 16, color: C.background2, valign: 'top' })
    ]
  })

  const card = (slide, x, y, w, h, name, fill = C.background2) => slide.addShape(pres.shapes.ROUNDED_RECTANGLE, { x, y, w, h, fill: { color: fill }, line: { color: fill, width: 0 }, rectRadius: 0.08, objectName: name })
  const chip = (slide, label, x, y, w, h, fill, size, name) => slide.addText(label, { x, y, w, h, shape: pres.shapes.ROUNDED_RECTANGLE, rectRadius: 0.06, fill: { color: fill }, color: C.background1, bold: true, fontSize: size, align: 'center', valign: 'middle', margin: 0, isTextBox: true, objectName: name })
  // An outlined chip for controls with no status: (null) or N/A.
  const hollowChip = (slide, x, y, w, h, name) => slide.addShape(pres.shapes.ROUNDED_RECTANGLE, { x, y, w, h, fill: { color: C.background1 }, line: { color: C.accent6, width: 1, dashType: 'dash' }, rectRadius: 0.06, objectName: name })
  // Figures and dates never break across lines: "14 of 36", "Feb 1, 2027", "36 min" are bound with
  // non-breaking spaces before they reach the slide.
  const MONTHS = 'Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec|January|February|March|April|June|July|August|September|October|November|December'
  const glue = t => String(t)
    .replace(/(\d[\d,.]*) of (\d[\d,.]*)/g, '$1\u00A0of\u00A0$2')
    .replace(new RegExp(`\\b(${MONTHS}) (\\d{1,2}), (\\d{4})`, 'g'), '$1\u00A0$2,\u00A0$3')
    .replace(new RegExp(`\\b(${MONTHS}) (\\d{4})`, 'g'), '$1\u00A0$2')
    .replace(/(\d) (min|hr|days|pts|points)\b/g, '$1\u00A0$2')
  const text = (slide, runs, opts) => slide.addText(Array.isArray(runs) ? runs.map(r => ({ ...r, text: glue(r.text) })) : glue(runs), { margin: 0, valign: 'top', isTextBox: true, ...opts })
  // A horizontal meter: a light track and a fill for the share.
  const meter = (slide, x, y, w, pct, fill, name) => {
    slide.addShape(pres.shapes.ROUNDED_RECTANGLE, { x, y, w, h: 0.14, fill: { color: C.background2 }, line: { color: C.background2, width: 0 }, rectRadius: 0.07, objectName: `${name} track` })
    const share = Math.max(0, Math.min(100, Number(pct) || 0)) / 100
    if (share > 0) slide.addShape(pres.shapes.ROUNDED_RECTANGLE, { x, y, w: Math.max(0.14, w * share), h: 0.14, fill: { color: fill }, line: { color: fill, width: 0 }, rectRadius: 0.07, objectName: `${name} fill` })
  }
  const rule = (slide, x, y, w, color, width, name) => slide.addShape(pres.shapes.LINE, { x, y, w, h: 0, line: { color, width }, objectName: name })
  const markFill = mark => ({ E: C.accent3, P: C.accent2, N: C.accent4 })[mark] || C.accent6
  return { pres, C, card, chip, hollowChip, text, meter, markFill, rule, glue }
}

// Greedy word wrap with average Arial widths, to size boxes. Errs on the wide side. A word longer than a line
// breaks across lines, as PowerPoint breaks it, and a non-breaking space joins two words into one.
function lines(value, width, size, bold = false) {
  const perLine = Math.max(1, Math.floor(width / (size / 72 * (bold ? 0.55 : 0.46))))
  let count = 1, used = 0
  for (const word of String(value ?? '').split(/[^\S\u00A0]+/).filter(Boolean)) {
    if (used > 0 && used + 1 + word.length > perLine) { count++; used = 0 }
    if (word.length > perLine) { count += Math.floor((word.length - 1) / perLine); used = (word.length - 1) % perLine + 1 }
    else used += (used ? 1 : 0) + word.length
  }
  return count
}

// pptxgenjs writes Office's stock palette into the theme. Replace it with the Atmosera colors so
// scheme colors resolve correctly, and refuse any color that is not six hex digits.
async function writeDeck(pres, file) {
  fs.mkdirSync(path.dirname(file), { recursive: true })
  await pres.writeFile({ fileName: file })
  const slots = ['dk1', 'lt1', 'dk2', 'lt2', 'accent1', 'accent2', 'accent3', 'accent4', 'accent5', 'accent6', 'hlink', 'folHlink']
  const zip = await JSZip.loadAsync(fs.readFileSync(file))
  const part = 'ppt/theme/theme1.xml'
  const scheme = `<a:clrScheme name="${THEME.name}">${slots.map(k => `<a:${k}><a:srgbClr val="${THEME.colors[k]}"/></a:${k}>`).join('')}</a:clrScheme>`
  const xml = (await zip.file(part).async('string')).replace(/<a:clrScheme\b[\s\S]*?<\/a:clrScheme>/, () => scheme).replace(/(<a:(?:theme|fontScheme)\b[^>]*?\bname=")[^"]*"/g, (_, head) => `${head}${THEME.name}"`)
  if (!xml.includes(scheme)) throw new Error('The theme part has no color scheme to replace.')
  zip.file(part, xml)
  // pptxgenjs 4.0.1 writes each chart's embedded table range as ref="A1:D4'". PowerPoint and
  // LibreOffice ignore it, but Keynote and Quick Look reject the workbook and drop the whole chart.
  for (const name of Object.keys(zip.files).filter(n => /^ppt\/embeddings\/.+\.xlsx$/.test(n))) {
    const book = await JSZip.loadAsync(await zip.file(name).async('nodebuffer'))
    for (const table of Object.keys(book.files).filter(n => /^xl\/tables\/.+\.xml$/.test(n))) {
      const fixed = (await book.file(table).async('string')).replace(/(<table\b[^>]*?\bref="[A-Z]+\d+:[A-Z]+\d+)'"/, '$1"')
      if (!/<table\b[^>]*?\bref="[A-Z]+\d+:[A-Z]+\d+"/.test(fixed)) throw new Error(`${name} ${table} has a table range the chart importers cannot read.`)
      book.file(table, fixed)
    }
    zip.file(name, await book.generateAsync({ type: 'nodebuffer', compression: 'DEFLATE' }))
  }
  for (const name of Object.keys(zip.files)) {
    if (!name.endsWith('.xml')) continue
    const bad = (await zip.file(name).async('string')).match(/<a:srgbClr val="((?![0-9A-Fa-f]{6}")[^"]*)"/)
    if (bad) throw new Error(`${name} has a color "${bad[1]}" that is not six hex digits. A scheme color was given to a hex-only option.`)
  }
  fs.writeFileSync(file, await zip.generateAsync({ type: 'nodebuffer', compression: 'DEFLATE' }))
  return file
}

module.exports = { createDeck, writeDeck, lines, THEME, HEX, W, H, X0, CW, JSZip }
