/* Presenter notes and evidence review for the internal edition of the HTML report (screen only). The builder embeds
   this script, the toolbar toggle and the aside only in 03-security-report.html. The client edition carries none of
   them, and its embedded data leaves out what only these notes read (Oct 16, 2026). */
(function () {
  'use strict'
  const { build, fmt, clean } = EbrReport
  const data = JSON.parse(document.getElementById('report-data').textContent)
  const m = build(data)
  // The CyberSOC monthly notes join the EBR ones, so the presenter sees both sets in one place.
  const cs = EbrCyberSoc.build(data, m)
  m.presenter.push(...cs.presenter)
  m.review.push(...cs.review)
  const esc = value => clean(value).replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/'/g, '&#39;')
  const review = document.getElementById('review')
  const rationale = m.timingRationale?.length ? `<h3>Response timing cohort</h3><p>One fixed cohort supplies the timing: every high severity alert created in the alert period and closed by collection, automation closures included. A median under 20 minutes or a 90th percentile over one hour is presented with a note, never replaced by another cohort or period. Fewer than 5 closed alerts withholds the figures.</p><div class="table-scroll"><table><thead><tr><th scope="col">Cohort</th><th scope="col">Closed alerts</th><th scope="col">Median to acknowledge</th><th scope="col">Median to close</th><th scope="col">90th percentile</th><th scope="col">Presentation</th></tr></thead><tbody>${m.timingRationale.map(r => `<tr><td>${esc(r.cohort)}</td><td>${fmt(r.n)}</td><td>${esc(r.acknowledge ?? 'Not available')}</td><td>${esc(r.median ?? 'Not available')}</td><td>${esc(r.p90 ?? 'Not available')}</td><td>${esc(r.status)}</td></tr>`).join('')}</tbody></table></div>` : ''
  review.innerHTML = `<div class="review-heading"><p class="eyebrow dark">Presenter notes</p><h2>Prepare the conversation</h2><p>These notes are for the Atmosera presenter and are excluded from printing. They list the figures that need a prepared answer, the reasons behind each presentation choice and the evidence that was not measured.</p></div>
    <h3>Prepared answers</h3><div class="review-notes">${m.presenter.length ? m.presenter.map(r => `<article><h3>${esc(r.title)}</h3><p>${esc(r.text)}</p></article>`).join('') : '<p class="small">No sensitive figures were flagged in this collection.</p>'}</div>
    ${rationale}
    <h3>Evidence review</h3><div class="review-notes">${m.review.map(r => `<article><h3>${esc(r.title)}</h3><p>${esc(r.text)}</p></article>`).join('')}</div>
    <h3>Collection register</h3><p class="small">${m.coverage.available} of ${m.coverage.total} primary result sets completed with an OK or EMPTY status. This is collection status, not a security score.</p><div class="table-scroll"><table><thead><tr><th scope="col">Evidence ID</th><th scope="col">Status</th><th scope="col">Rows</th><th scope="col">Read date</th></tr></thead><tbody>${m.manifest.map(r => `<tr><th scope="row">${esc(r.id)}</th><td>${esc(r.status)}</td><td>${fmt(r.rows)}</td><td>${esc(r.date)}</td></tr>`).join('')}</tbody></table></div>`
  document.getElementById('review-toggle').addEventListener('click', function () {
    review.hidden = !review.hidden
    this.setAttribute('aria-expanded', String(!review.hidden))
    if (!review.hidden) review.scrollIntoView({ behavior: 'smooth', block: 'start' })
  })
})()
