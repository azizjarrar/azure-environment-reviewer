// DOM references — cached once at startup to avoid repeated lookups.
const form = document.getElementById('creds-form');
const submitBtn = document.getElementById('submit-btn');
const btnText = submitBtn.querySelector('.btn-text');
const btnSpinner = submitBtn.querySelector('.btn-spinner');
const errorBanner = document.getElementById('error-banner');
const errorText = document.getElementById('error-text');

// Matches a standard Azure GUID (tenantId, clientId, subscriptionId).
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

// Displays an error message in the banner and scrolls it into view.
function showError(msg) {
  errorText.textContent = msg;
  errorBanner.classList.remove('hidden');
  errorBanner.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

// Hides the error banner.
function clearError() {
  errorBanner.classList.add('hidden');
}

// Toggles the submit button between its normal state and a loading/spinner state.
function setLoading(on) {
  submitBtn.disabled = on;
  btnText.classList.toggle('hidden', on);
  btnSpinner.classList.toggle('hidden', !on);
}

// Validates a single credential input field.
// clientSecret: must be at least 8 characters.
// All other fields: must match the Azure GUID format.
// Only marks the field invalid after the user has typed something (avoids false negatives on empty focus).
function validateField(input) {
  const val = input.value.trim();
  if (input.id === 'clientSecret') {
    const ok = val.length >= 8;
    input.classList.toggle('invalid', !ok);
    return ok;
  }
  const ok = UUID_RE.test(val);
  input.classList.toggle('invalid', !ok && val.length > 0);
  return ok;
}

// Attach inline validation to UUID fields: validate on blur, clear the error style on any input.
['tenantId', 'clientId', 'subscriptionId'].forEach(id => {
  const el = document.getElementById(id);
  el.addEventListener('blur', () => validateField(el));
  el.addEventListener('input', () => el.classList.remove('invalid'));
});

// Toggle password field visibility for any button with class .toggle-vis.
// The button's data-target attribute holds the ID of the input to toggle.
document.querySelectorAll('.toggle-vis').forEach(btn => {
  btn.addEventListener('click', () => {
    const target = document.getElementById(btn.dataset.target);
    target.type = target.type === 'password' ? 'text' : 'password';
  });
});

// Auto-fill form from .env dev credentials (dev only — server returns empty strings in prod).
(async () => {
  try {
    const res = await fetch('/api/auth/dev-creds');
    if (!res.ok) return;
    const creds = await res.json();
    if (creds.tenantId)       document.getElementById('tenantId').value       = creds.tenantId;
    if (creds.clientId)       document.getElementById('clientId').value       = creds.clientId;
    if (creds.clientSecret)   document.getElementById('clientSecret').value   = creds.clientSecret;
    if (creds.subscriptionId) document.getElementById('subscriptionId').value = creds.subscriptionId;
  } catch { /* dev-creds unavailable — silently skip */ }
})();

// Form submit handler — validates all fields client-side, then POSTs to /api/auth/connect.
// On success the server stores creds in the session and we redirect to the review dashboard.
form.addEventListener('submit', async (e) => {
  e.preventDefault();
  clearError();

  const fields = {
    tenantId:       document.getElementById('tenantId').value.trim(),
    clientId:       document.getElementById('clientId').value.trim(),
    clientSecret:   document.getElementById('clientSecret').value.trim(),
    subscriptionId: document.getElementById('subscriptionId').value.trim(),
  };

  // Client-side guard — mirrors the server-side validation in routes/auth.js.
  if (!UUID_RE.test(fields.tenantId))       return showError('Tenant ID must be a valid GUID.');
  if (!UUID_RE.test(fields.clientId))       return showError('Client ID must be a valid GUID.');
  if (fields.clientSecret.length < 8)       return showError('Client Secret appears too short.');
  if (!UUID_RE.test(fields.subscriptionId)) return showError('Subscription ID must be a valid GUID.');

  setLoading(true);

  try {
    const res = await fetch('/api/auth/connect', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(fields),
    });

    const data = await res.json();

    if (!res.ok) {
      showError(data.error || 'Connection failed. Check your credentials and try again.');
      return;
    }

    window.location.href = '/review';
  } catch {
    showError('Network error — is the server running?');
  } finally {
    setLoading(false);
  }
});
