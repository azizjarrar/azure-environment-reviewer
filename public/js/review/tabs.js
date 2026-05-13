function activateTab(section) {
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.toggle('active', b.dataset.section === section));
  document.querySelectorAll('.tab-panel').forEach(p => p.classList.toggle('active', p.id === `panel-${section}`));
}

function setTabStatus(key, state) {
  const el = document.getElementById(`status-${key}`);
  if (el) el.className = `tab-status ${state}`;
}

function setTabBadge(key, count) {
  const el = document.getElementById(`badge-${key}`);
  if (!el) return;
  el.textContent = count;
  el.classList.remove('hidden');
}

document.querySelectorAll('.tab-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    const section = btn.dataset.section;
    activateTab(section);
    if (section === 'ai') loadAIReportList();
  });
});
