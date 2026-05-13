function setLoading(on) {
  runBtn.disabled = on;
  runBtn.querySelector('.btn-text').classList.toggle('hidden', on);
  runBtn.querySelector('.btn-spinner').classList.toggle('hidden', !on);
}

function showError(msg) {
  errorMsg.textContent = msg;
  errorState.classList.remove('hidden');
}

function hideError() {
  errorState.classList.add('hidden');
}

function resetResults() {
  resourcesBySection = {};
  if (pdfBtn) pdfBtn.classList.add('hidden');
  document.getElementById('badge-ai').classList.add('hidden');
  totalCount.textContent = '';
  scanTime.textContent = '';
  emptyState.classList.add('hidden');

  SECTIONS.forEach(s => {
    setTabStatus(s.key, '');
    const badge = document.getElementById(`badge-${s.key}`);
    if (badge) { badge.textContent = ''; badge.classList.add('hidden'); }
    const body = document.getElementById(`body-${s.key}`);
    if (body) body.innerHTML = '';
  });

  document.getElementById('overview-grid').innerHTML = '';
  const overBadge = document.getElementById('badge-overview');
  if (overBadge) { overBadge.textContent = ''; overBadge.classList.add('hidden'); }

  activateTab('overview');
}
