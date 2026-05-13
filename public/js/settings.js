// ─── DOM refs ──────────────────────────────────────────────────────────────────
const credList     = document.getElementById('cred-list');
const addCredBtn   = document.getElementById('add-cred-btn');
const formWrap     = document.getElementById('cred-form-wrap');
const formTitle    = document.getElementById('cred-form-title');
const cancelBtn    = document.getElementById('cancel-form-btn');
const saveBtn      = document.getElementById('save-cred-btn');
const saveBtnText  = document.getElementById('save-btn-text');
const saveBtnSpin  = document.getElementById('save-btn-spinner');
const formError    = document.getElementById('form-error');
const formErrorTxt = document.getElementById('form-error-text');
const toastWrap    = document.getElementById('toast-wrap');

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

let editingId = null; // null = adding new, string = editing existing

// ─── Toast ────────────────────────────────────────────────────────────────────
function toast(msg, type = 'success') {
  const el = document.createElement('div');
  el.className = `toast ${type}`;
  el.innerHTML = `
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
      ${type === 'success'
        ? '<circle cx="12" cy="12" r="9"/><polyline points="8 12 11 15 16 9"/>'
        : '<circle cx="12" cy="12" r="9"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>'}
    </svg>
    ${escHtml(msg)}
  `;
  toastWrap.appendChild(el);
  setTimeout(() => el.remove(), 4000);
}

// ─── Load user profile ────────────────────────────────────────────────────────
async function loadUser() {
  try {
    const res  = await fetch('/api/users/me');
    if (!res.ok) { window.location.href = '/login'; return; }
    const { user } = await res.json();

    const initials = user.name.split(' ').map(n => n[0]).join('').toUpperCase().slice(0, 2);
    document.getElementById('user-initials').textContent  = initials;
    document.getElementById('user-name-bar').textContent  = user.name;
    document.getElementById('profile-avatar').textContent = initials;
    document.getElementById('profile-name').textContent   = user.name;
    document.getElementById('profile-email').textContent  = user.email;
    document.getElementById('profile-meta').textContent   =
      `Member since ${new Date(user.createdAt).toLocaleDateString()}`;
  } catch {
    window.location.href = '/login';
  }
}

// ─── Load credential list ─────────────────────────────────────────────────────
async function loadCredentials() {
  const res  = await fetch('/api/credentials');
  if (!res.ok) return;
  const { credentials } = await res.json();
  renderCredList(credentials);
}

function renderCredList(credentials) {
  if (!credentials.length) {
    credList.innerHTML = `
      <div class="cred-empty">
        <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="#c8d6e5" stroke-width="1.2">
          <rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>
        </svg>
        <h3>No credentials yet</h3>
        <p>Add your Azure Service Principal to start running reviews.</p>
      </div>`;
    return;
  }

  credList.innerHTML = '';
  credentials.forEach(cred => {
    const card = document.createElement('div');
    card.className = `cred-card${cred.isActive ? ' is-active' : ''}`;
    card.dataset.id = cred._id;

    const subShort = cred.subscriptionId
      ? '…' + cred.subscriptionId.slice(-8)
      : '—';

    card.innerHTML = `
      <div class="cred-card-icon">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#0078D4" stroke-width="2">
          <rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>
        </svg>
      </div>
      <div class="cred-card-info">
        <div class="cred-card-label">
          ${escHtml(cred.label)}
          ${cred.isActive ? '<span class="badge-active">Active</span>' : ''}
        </div>
        <div class="cred-card-meta">
          Sub: ${escHtml(subShort)} &nbsp;·&nbsp; Client: …${escHtml(cred.clientId.slice(-6))}
        </div>
      </div>
      <div class="cred-card-actions">
        ${!cred.isActive
          ? `<button class="btn-sm" data-action="activate" data-id="${cred._id}">Set Active</button>`
          : ''}
        <button class="btn-sm" data-action="test" data-id="${cred._id}">Test</button>
        <button class="btn-icon" data-action="edit" data-id="${cred._id}" title="Edit">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/>
            <path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/>
          </svg>
        </button>
        <button class="btn-icon danger" data-action="delete" data-id="${cred._id}" title="Delete">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/>
            <path d="M10 11v6M14 11v6"/><path d="M9 6V4h6v2"/>
          </svg>
        </button>
      </div>
    `;

    credList.appendChild(card);
  });
}

// ─── Credential actions ───────────────────────────────────────────────────────
credList.addEventListener('click', async (e) => {
  const btn = e.target.closest('[data-action]');
  if (!btn) return;
  const { action, id } = btn.dataset;

  if (action === 'activate') {
    btn.textContent = '…';
    btn.disabled = true;
    const res = await fetch(`/api/credentials/${id}/activate`, { method: 'POST' });
    if (res.ok) { toast('Credential set as active.'); await loadCredentials(); }
    else        { toast('Failed to activate.', 'error'); btn.disabled = false; btn.textContent = 'Set Active'; }
  }

  if (action === 'test') {
    btn.textContent = 'Testing…';
    btn.disabled = true;
    const res  = await fetch(`/api/credentials/${id}/test`, { method: 'POST' });
    const data = await res.json();
    btn.textContent = 'Test';
    btn.disabled = false;
    if (data.valid) toast('Credentials are valid and connected to Azure.');
    else            toast('Credentials failed: ' + (data.error || 'Unknown error'), 'error');
  }

  if (action === 'edit') {
    openEditForm(id);
  }

  if (action === 'delete') {
    if (!confirm('Delete this credential set? This cannot be undone.')) return;
    const res = await fetch(`/api/credentials/${id}`, { method: 'DELETE' });
    if (res.ok) { toast('Credential deleted.'); await loadCredentials(); }
    else        toast('Failed to delete.', 'error');
  }
});

// ─── Form open/close ──────────────────────────────────────────────────────────
addCredBtn.addEventListener('click', () => {
  editingId = null;
  clearForm();
  formTitle.textContent = 'Add Azure Credential';
  saveBtnText.textContent = 'Validate & Save';
  document.getElementById('secret-hint').textContent = 'Encrypted with AES-256-GCM before storing';
  document.getElementById('cred-secret').required = true;
  formWrap.classList.add('open');
  formWrap.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
});

cancelBtn.addEventListener('click', closeForm);

function openEditForm(id) {
  editingId = id;
  clearForm();
  formTitle.textContent = 'Edit Azure Credential';
  saveBtnText.textContent = 'Save Changes';
  document.getElementById('secret-hint').textContent = 'Leave blank to keep existing secret';
  document.getElementById('cred-secret').required = false;

  // Pre-fill what we have (secret is not returned from API)
  const card = credList.querySelector(`[data-id="${id}"]`);
  if (card) {
    const label = card.querySelector('.cred-card-label').childNodes[0].textContent.trim();
    document.getElementById('cred-label').value = label;
  }

  formWrap.classList.add('open');
  formWrap.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

function closeForm() {
  formWrap.classList.remove('open');
  editingId = null;
  clearForm();
}

function clearForm() {
  ['cred-label','cred-tenant','cred-client','cred-secret','cred-sub'].forEach(id => {
    document.getElementById(id).value = '';
  });
  formError.classList.add('hidden');
}

function showFormError(msg) {
  formErrorTxt.textContent = msg;
  formError.classList.remove('hidden');
}

// ─── Save credential ──────────────────────────────────────────────────────────
saveBtn.addEventListener('click', async () => {
  formError.classList.add('hidden');

  const label    = document.getElementById('cred-label').value.trim();
  const tenantId = document.getElementById('cred-tenant').value.trim();
  const clientId = document.getElementById('cred-client').value.trim();
  const secret   = document.getElementById('cred-secret').value;
  const subId    = document.getElementById('cred-sub').value.trim();

  // Validate only filled fields; for edit, secret is optional
  if (!UUID_RE.test(tenantId))       return showFormError('Invalid Tenant ID — must be a GUID.');
  if (!UUID_RE.test(clientId))       return showFormError('Invalid Client ID — must be a GUID.');
  if (!editingId && secret.length < 8)  return showFormError('Client Secret must be at least 8 characters.');
  if (secret && secret.length < 8)   return showFormError('Client Secret must be at least 8 characters.');
  if (!UUID_RE.test(subId))          return showFormError('Invalid Subscription ID — must be a GUID.');

  setSaveLoading(true);
  try {
    const body = { label: label || 'Default', tenantId, clientId, subscriptionId: subId };
    if (secret) body.clientSecret = secret;

    const url    = editingId ? `/api/credentials/${editingId}` : '/api/credentials';
    const method = editingId ? 'PUT' : 'POST';

    const res  = await fetch(url, {
      method,
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify(body),
    });
    const data = await res.json();

    if (!res.ok) return showFormError(data.error || 'Save failed.');

    toast(editingId ? 'Credential updated.' : 'Credential saved and validated.');
    closeForm();
    await loadCredentials();
  } catch {
    showFormError('Network error. Try again.');
  } finally {
    setSaveLoading(false);
  }
});

function setSaveLoading(on) {
  saveBtn.disabled = on;
  saveBtnText.classList.toggle('hidden', on);
  saveBtnSpin.classList.toggle('hidden', !on);
}

// ─── Password toggle in form ──────────────────────────────────────────────────
document.querySelectorAll('.toggle-vis').forEach(btn => {
  btn.addEventListener('click', () => {
    const target = document.getElementById(btn.dataset.target);
    target.type = target.type === 'password' ? 'text' : 'password';
  });
});

// ─── Logout ───────────────────────────────────────────────────────────────────
document.getElementById('logout-btn').addEventListener('click', async () => {
  await fetch('/api/users/logout', { method: 'POST' });
  window.location.href = '/';
});

// ─── Util ─────────────────────────────────────────────────────────────────────
function escHtml(str) {
  return String(str ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

// ─── Load AI usage ────────────────────────────────────────────────────────────
async function loadUsage() {
  const el = document.getElementById('ai-usage-content');
  try {
    const res = await fetch('/api/users/usage');
    if (!res.ok) { el.textContent = 'Could not load usage data.'; return; }
    const { totalInputTokens, totalOutputTokens, totalCostUSD, reportCount, chatCount } = await res.json();

    el.innerHTML = `
      <div class="usage-grid">
        <div class="usage-stat">
          <div class="usage-stat-value">$${totalCostUSD.toFixed(4)}</div>
          <div class="usage-stat-label">Total Cost</div>
        </div>
        <div class="usage-stat">
          <div class="usage-stat-value">${totalInputTokens.toLocaleString()}</div>
          <div class="usage-stat-label">Input Tokens</div>
        </div>
        <div class="usage-stat">
          <div class="usage-stat-value">${totalOutputTokens.toLocaleString()}</div>
          <div class="usage-stat-label">Output Tokens</div>
        </div>
        <div class="usage-stat">
          <div class="usage-stat-value">${reportCount}</div>
          <div class="usage-stat-label">Reports</div>
        </div>
        <div class="usage-stat">
          <div class="usage-stat-value">${chatCount}</div>
          <div class="usage-stat-label">Chat Messages</div>
        </div>
      </div>
      <p class="usage-note">Pricing: $2.00 / 1M input tokens &nbsp;·&nbsp; $8.00 / 1M output tokens (GPT-4.1)</p>
    `;
  } catch {
    el.textContent = 'Could not load usage data.';
  }
}

// ─── Init ─────────────────────────────────────────────────────────────────────
loadUser();
loadCredentials();
loadUsage();
