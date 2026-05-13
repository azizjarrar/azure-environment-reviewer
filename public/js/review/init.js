(async () => {
  try {
    const [statusRes, userRes, aiStatusRes] = await Promise.all([
      fetch('/api/review/status'),
      fetch('/api/users/me'),
      fetch('/api/ai/status'),
    ]);

    const status = await statusRes.json();
    const subBadge = document.getElementById('sub-badge');
    if (!status.connected) {
      subBadge.textContent = 'No credentials';
      subBadge.style.background = '#fff3e0';
      subBadge.style.color = '#b45309';
    } else {
      subBadge.textContent = status.label
        ? `${status.label} · …${status.subscriptionId.slice(-6)}`
        : status.subscriptionId;
    }

    if (userRes.ok) {
      const { user } = await userRes.json();
      const initials = user.name.split(' ').map(n => n[0]).join('').toUpperCase().slice(0, 2);
      document.getElementById('user-initials-bar').textContent = initials;
      document.getElementById('user-name-bar').textContent = user.name;
    }

    if (aiStatusRes.ok) {
      const aiStatus = await aiStatusRes.json();
      if (!aiStatus.available) {
        aiBtn.disabled = true;
        aiBtn.title = aiStatus.message;
        aiBtn.style.opacity = '0.45';
        aiBtn.style.cursor = 'not-allowed';
        const aiTab = document.querySelector('.tab-btn[data-section="ai"]');
        if (aiTab) { aiTab.style.opacity = '0.45'; aiTab.title = aiStatus.message; }
      }
    }
  } catch { /* best-effort */ }
})();

if (pdfBtn) {
  pdfBtn.addEventListener('click', () => {
    const qs = selectedReviewId ? `?reviewId=${encodeURIComponent(selectedReviewId)}` : '';
    window.location.href = `/api/ai/pdf${qs}`;
  });
}

document.getElementById('logout-btn').addEventListener('click', async () => {
  if (activeStream) activeStream.close();
  await fetch('/api/users/logout', { method: 'POST' });
  window.location.href = '/';
});

loadReviews();
