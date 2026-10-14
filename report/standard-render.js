/* Standards edition of page 04, The controls that matter. Informational: it outlines the controls
   for executives and invites feedback, it does not ask for sign-off.
   The control list, tiers and measure text come from the report model run on an empty pack in
   standards mode, so this document always matches the controls page of the client report. */
(function () {
  'use strict'
  const { build, clean } = EbrReport
  const data = JSON.parse(document.getElementById('report-data').textContent)
  const m = build(data)
  const info = data.standardInfo || {}
  const esc = value => clean(value).replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/'/g, '&#39;')
  const report = document.getElementById('report')
  const groups = ['Identity and access', 'Endpoint and workload', 'Network and boundary', 'Data protection', 'Detection and response']
  const tiers = [['foundational', 'Foundational', 'F'], ['defense', 'Defense in depth', 'D']]
  const title = clean(info.Title) || 'The controls that matter'
  const version = clean(info.Version)
  const heading = (n, text, subtitle) => `<header class="section-heading"><p class="eyebrow">Controls standard · ${n}</p><h2>${esc(text)}</h2><p>${esc(subtitle)}</p></header>`
  const inTier = (group, tier) => m.controls.filter(c => c.group === group && c.tier === tier)
  const total = tier => m.controls.filter(c => c.tier === tier).length

  // 01 Overview
  const counts = groups.map(g => `<tr><th scope="row">${esc(g)}</th>${tiers.map(([t]) => `<td>${inTier(g, t).length}</td>`).join('')}<td>${m.controls.filter(c => c.group === g).length}</td></tr>`).join('')
  const cover = `<section class="page summary-page" id="overview">
    <header class="hero"><p class="eyebrow">Managed security services · Security controls standard</p><h1>${esc(title)}</h1><div class="hero-rule"></div><p class="hero-client">MXDR security controls standard</p><p class="hero-caption">The controls every managed environment is held to, and how each one is measured.</p><p class="hero-meta">${version ? `Version ${esc(version)} · ` : ''}${total('foundational')} foundational and ${total('defense')} defense in depth controls across five pillars</p></header>
    <div class="page-body">
      <div class="legend-box"><h3>Two tiers of controls</h3><p><strong>Foundational</strong> controls are configured when the environment is built and are expected to stay enforced at every review. One that reads below E is treated as drift and carries a fix date. <strong>Defense in depth</strong> controls are the additional safeguards layered on afterward. Each waits on something the client approves, schedules or licenses, and they are sequenced on the roadmap.</p>
      <h3>How each control is graded</h3><p><span class="mark mark-e">E</span> Enforced on 90 percent or more of in-scope resources. <span class="mark mark-p">P</span> Partial, enforced on 50 to 89 percent. <span class="mark mark-n">N</span> Not yet enforced, under 50 percent. A control read from a policy or tenant setting rather than a count reads In force or Not in force. A control with no activity or configuration to judge it by reads N/A and is left out of every count.</p></div>
      <div class="two-up">
        <div><h3>A control is foundational when all three hold</h3><ol class="criteria"><li>Other controls in the pillar depend on it.</li><li>It applies to every client in scope of the service.</li><li>Atmosera can deliver it inside the build window.</li></ol></div>
        <div><h3>A control is defense in depth when any one is true</h3><ul class="criteria"><li>It needs application or dependency testing only the client can perform.</li><li>It needs a maintenance window, a reboot or a redeployment.</li><li>It changes network or directory architecture.</li><li>It needs licensing or recurring cost beyond the service agreement.</li><li>It depends on tuning against the environment's own operating history.</li></ul></div>
      </div>
      <div class="pillar-counts"><h3>Controls by pillar</h3><table class="count-table"><thead><tr><th scope="col">Pillar</th>${tiers.map(([, label]) => `<th scope="col">${esc(label)}</th>`).join('')}<th scope="col">Total</th></tr></thead><tbody>${counts}</tbody><tfoot><tr><th scope="row">All pillars</th>${tiers.map(([t]) => `<td>${total(t)}</td>`).join('')}<td>${m.controls.length}</td></tr></tfoot></table></div>
    </div></section>`

  // 02 The controls, by pillar and tier
  const row = (c, i, letter) => `<div class="control-row standard-row"><span class="mark mark-${letter.toLowerCase()}" title="${letter === 'F' ? 'Foundational' : 'Defense in depth'}">${letter}${i + 1}</span><div class="control-text"><h4>${esc(c.label)}</h4><p>${esc(c.note)}</p></div></div>`
  const matrix = groups.map((group, n) => `<section class="pillar"><div class="pillar-head"><span>0${n + 1}</span><h3>${esc(group)}</h3><p class="small">${inTier(group, 'foundational').length} foundational · ${inTier(group, 'defense').length} defense in depth</p></div><div class="control-list">${tiers.map(([tier, label, letter]) => `<div class="control-col ${tier}"><p class="tier-label"><span class="tier-name">${esc(label)}</span><span class="tier-count">${inTier(group, tier).length} controls</span></p>${inTier(group, tier).map((c, i) => row(c, i, letter)).join('')}</div>`).join('')}</div></section>`).join('')
  const controls = `<section class="page" id="controls">${heading('02', title, 'Every control by pillar and tier, with the reading that grades it')}
    <div class="page-body"><p class="section-scope">Activity lookbacks are stated with each control.</p>
    <div class="control-matrix">${matrix}</div>
    <div class="decision-note"><h3>Feedback</h3><p>Feedback on any control, its tier or how it is measured is welcome and is weighed for the next version of this standard.</p></div></div></section>`

  report.innerHTML = cover + controls
  document.getElementById('print').addEventListener('click', () => window.print())
})()
