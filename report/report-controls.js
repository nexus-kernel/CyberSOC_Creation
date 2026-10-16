/* The toolbar of both HTML editions: the depth selector and the print button. The internal edition runs it after
   report-render.js. The client edition carries the pages already rendered, so this is the only script it holds. */
(function () {
  'use strict'
  const depth = document.getElementById('depth')
  function setDepth() {
    document.body.dataset.depth = depth.value
    document.querySelectorAll('.additional, .data-details').forEach(d => { d.open = depth.value === 'detailed' })
  }
  depth.addEventListener('change', setDepth)
  setDepth()
  document.getElementById('print').addEventListener('click', () => window.print())
})()
