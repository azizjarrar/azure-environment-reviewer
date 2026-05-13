const form       = document.getElementById('login-form');
const submitBtn  = document.getElementById('submit-btn');
const errorBanner = document.getElementById('error-banner');
const errorText  = document.getElementById('error-text');

function showError(msg) {
  errorText.textContent = msg;
  errorBanner.classList.remove('hidden');
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

  const email    = document.getElementById('email').value.trim();
  const password = document.getElementById('password').value;

  if (!email)    return showError('Email is required.');
  if (!password) return showError('Password is required.');

  setLoading(true);
  try {
    const res  = await fetch('/api/users/login', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ email, password }),
    });
    const data = await res.json();

    if (!res.ok) return showError(data.error || 'Sign in failed.');
    window.location.href = '/review';
  } catch {
    showError('Network error — is the server running?');
  } finally {
    setLoading(false);
  }
});
