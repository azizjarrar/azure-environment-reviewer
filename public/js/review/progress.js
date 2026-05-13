function iconWaiting() {
  return `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#ccc" stroke-width="2"><circle cx="12" cy="12" r="9"/></svg>`;
}
function iconSpinning() {
  return `<svg class="spinning" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
    <path d="M12 2v4M12 18v4M4.93 4.93l2.83 2.83M16.24 16.24l2.83 2.83M2 12h4M18 12h4M4.93 19.07l2.83-2.83M16.24 7.76l2.83-2.83"/>
  </svg>`;
}
function iconDone() {
  return `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="9"/><polyline points="8 12 11 15 16 9"/></svg>`;
}
function iconError() {
  return `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="9"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>`;
}

function showProgress() {
  progressSects.innerHTML = '';
  progressPanel.classList.remove('hidden');
  for (const s of SECTIONS) {
    const row = document.createElement('div');
    row.className = 'progress-row';
    row.id = `prog-${s.key}`;
    row.innerHTML = `<span class="progress-icon">${iconWaiting()}</span><span>${escHtml(s.label)}</span>`;
    progressSects.appendChild(row);
  }
}

function setProgressRow(key, state, count = 0) {
  const row = document.getElementById(`prog-${key}`);
  if (!row) return;
  row.className = `progress-row ${state}`;
  const icon = state === 'scanning' ? iconSpinning()
             : state === 'done'     ? iconDone()
             :                        iconError();
  const countHtml = state === 'done' ? ` <span class="progress-count">${count}</span>` : '';
  const label = SECTIONS.find(s => s.key === key)?.label || key;
  row.innerHTML = `<span class="progress-icon">${icon}</span><span>${escHtml(label)}</span>${countHtml}`;
}
