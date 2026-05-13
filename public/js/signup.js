const form        = document.getElementById('signup-form');
const submitBtn   = document.getElementById('submit-btn');
const errorBanner = document.getElementById('error-banner');
const errorText   = document.getElementById('error-text');

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function showError(msg) {
  errorText.textContent = msg;
  errorBanner.classList.remove('hidden');
  errorBanner.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

function clearError() {
  errorBanner.classList.add('hidden');
}

function setLoading(on) {
  submitBtn.disabled = on;
  submitBtn.querySelector('.btn-text').classList.toggle('hidden', on);
  submitBtn.querySelector('.btn-spinner').classList.toggle('hidden', !on);
}

document.querySelectorAll('.toggle-vis').forEach(btn => {
  btn.addEventListener('click', () => {
    const target = document.getElementById(btn.dataset.target);
    target.type = target.type === 'password' ? 'text' : 'password';
  });
});

form.addEventListener('submit', async (e) => {
  e.preventDefault();
  clearError();

  const name     = document.getElementById('name').value.trim();
  const email    = document.getElementById('email').value.trim();
  const password = document.getElementById('password').value;
  const confirm  = document.getElementById('confirm').value;

  if (name.length < 2)          return showError('Name must be at least 2 characters.');
  if (!EMAIL_RE.test(email))    return showError('Please enter a valid email address.');
  if (password.length < 8)      return showError('Password must be at least 8 characters.');
  if (password !== confirm)     return showError('Passwords do not match.');

  setLoading(true);
  try {
    const res  = await fetch('/api/users/signup', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ name, email, password }),
    });
    const data = await res.json();

    if (!res.ok) return showError(data.error || 'Signup failed.');
    // New user → go to settings to add Azure credentials
    window.location.href = '/settings';
  } catch {
    showError('Network error — is the server running?');
  } finally {
    setLoading(false);
  }
});
