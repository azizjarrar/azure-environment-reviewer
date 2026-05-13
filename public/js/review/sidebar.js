async function loadReviews() {
  try {
    const res = await fetch('/api/review/list');
    if (!res.ok) return;
    const { reviews } = await res.json();
    reviewSelector.innerHTML = '';

    if (!reviews.length) {
      reviewSelector.innerHTML = '<option value="">No reviews yet</option>';
      return;
    }

    const placeholder = document.createElement('option');
    placeholder.value = '';
    placeholder.textContent = '— Select a review —';
    reviewSelector.appendChild(placeholder);

    for (const r of reviews) {
      const opt = document.createElement('option');
      opt.value = r.reviewId;
      const date = new Date(r.createdAt).toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric' });
      const statusIcon = r.status === 'running' ? ' ⏳' : r.status === 'error' ? ' ✕' : '';
      opt.textContent = `${r.name}${statusIcon} · ${date}`;
      if (r.reviewId === selectedReviewId) opt.selected = true;
      reviewSelector.appendChild(opt);
    }
  } catch { /* best-effort */ }
}

reviewSelector.addEventListener('change', async () => {
  const reviewId = reviewSelector.value;
  if (!reviewId) return;

  selectedReviewId = reviewId;
  resetResults();
  hideError();

  try {
    const res = await fetch(`/api/review/${reviewId}/sections`);
    if (!res.ok) { showError('Failed to load review data.'); return; }
    const { sections, summary, name, createdAt } = await res.json();

    if (summary) {
      renderOverview(summary);
      totalCount.textContent = `${summary.total} total resources`;
      scanTime.textContent = `Review: ${name} · ${new Date(createdAt).toLocaleString()}`;
      if (pdfBtn) pdfBtn.classList.remove('hidden');
      document.getElementById('badge-ai').classList.remove('hidden');
    }

    for (const [key, resources] of Object.entries(sections)) {
      if (Array.isArray(resources) && resources.length) {
        resourcesBySection[key] = resources;
        setTabBadge(key, resources.length);
        renderSection(key, resources);
      }
    }
  } catch (err) {
    showError('Failed to load review: ' + err.message);
  }
});

document.getElementById('refresh-reviews-btn').addEventListener('click', loadReviews);
