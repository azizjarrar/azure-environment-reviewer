function openRunModal() {
  reviewNameInput.value = '';
  document.getElementById('run-modal-sub-label').textContent =
    document.getElementById('sub-badge').textContent || '—';
  runModal.classList.remove('hidden');
  setTimeout(() => reviewNameInput.focus(), 80);
}

function closeRunModal() {
  runModal.classList.add('hidden');
}

document.getElementById('run-modal-close').addEventListener('click', closeRunModal);
runModal.addEventListener('click', e => { if (e.target === runModal) closeRunModal(); });
reviewNameInput.addEventListener('keydown', e => { if (e.key === 'Enter') confirmRunBtn.click(); });

runBtn.addEventListener('click', () => {
  if (activeStream) return;
  openRunModal();
});

confirmRunBtn.addEventListener('click', () => {
  const name = reviewNameInput.value.trim() || 'Unnamed Review';
  closeRunModal();
  startReview(name);
});

function startReview(name) {
  if (activeStream) { activeStream.close(); activeStream = null; }

  selectedReviewId = null;
  setLoading(true);
  hideError();
  resetResults();
  showProgress();

  activeStream = new EventSource(`/api/review/stream?sections=all&name=${encodeURIComponent(name)}`);

  activeStream.addEventListener('scan_init', e => {
    const data = JSON.parse(e.data);
    selectedReviewId = data.reviewId;
    loadReviews();
  });

  activeStream.addEventListener('start', e => {
    const { section } = JSON.parse(e.data);
    setTabStatus(section, 'scanning');
    setProgressRow(section, 'scanning');
  });

  activeStream.addEventListener('section_done', e => {
    const { section, resources } = JSON.parse(e.data);
    resourcesBySection[section] = resources;
    setTabStatus(section, 'done');
    setTabBadge(section, resources.length);
    setProgressRow(section, 'done', resources.length);
    renderSection(section, resources);
  });

  activeStream.addEventListener('section_error', e => {
    const { section, error } = JSON.parse(e.data);
    setTabStatus(section, 'error');
    setProgressRow(section, 'error');
    console.warn(`[${section}] error:`, error);
  });

  activeStream.addEventListener('complete', e => {
    const { summary, generatedAt, reviewId } = JSON.parse(e.data);
    selectedReviewId = reviewId || null;
    renderOverview(summary);
    scanTime.textContent = `Last scan: ${new Date(generatedAt).toLocaleString()}`;
    totalCount.textContent = `${summary.total} total resources`;
    if (pdfBtn) pdfBtn.classList.remove('hidden');
    document.getElementById('badge-ai')?.classList.remove('hidden');
    progressPanel.classList.add('hidden');
    setLoading(false);
    activeStream.close();
    activeStream = null;
    loadReviews();
  });

  activeStream.addEventListener('error', e => {
    let msg = 'Scan failed.';
    try { msg = JSON.parse(e.data).message; } catch { /* use default */ }
    showError(msg);
    setLoading(false);
    progressPanel.classList.add('hidden');
    activeStream.close();
    activeStream = null;
  });

  activeStream.onerror = () => {
    if (activeStream?.readyState === EventSource.CLOSED) setLoading(false);
  };
}
