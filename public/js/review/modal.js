function openModal(title, tableHtml) {
  document.getElementById('modal-title').textContent = title;
  document.getElementById('modal-body').innerHTML = `<div class="table-wrap">${tableHtml}</div>`;
  document.getElementById('detail-modal').classList.remove('hidden');
}

function closeModal() {
  document.getElementById('detail-modal').classList.add('hidden');
  document.getElementById('modal-body').innerHTML = '';
}

document.getElementById('modal-close').addEventListener('click', closeModal);
document.getElementById('detail-modal').addEventListener('click', e => {
  if (e.target === e.currentTarget) closeModal();
});
document.addEventListener('keydown', e => { if (e.key === 'Escape') closeModal(); });
document.addEventListener('click', e => {
  const btn = e.target.closest('.view-sub-btn');
  if (!btn) return;
  const entry = modalStore[btn.dataset.modalKey];
  if (entry) openModal(entry.title, entry.html);
});
