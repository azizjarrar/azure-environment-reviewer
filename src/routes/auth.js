const express = require('express');
const router = express.Router();
const { validateCredentials } = require('../utils/azureClient');

// Matches a standard Azure GUID (e.g. tenantId, clientId, subscriptionId).
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

// POST /api/auth/connect
// Validates the submitted Service Principal credentials against Azure AD.
// If valid, stores them in the server-side session and lets the client redirect to /review.
// Returns 401 if Azure rejects the credentials, 400 if any field is malformed.
router.post('/connect', async (req, res) => {
  const { tenantId, clientId, clientSecret, subscriptionId } = req.body || {};

  if (!UUID_RE.test(tenantId))       return res.status(400).json({ error: 'Invalid Tenant ID format.' });
  if (!UUID_RE.test(clientId))       return res.status(400).json({ error: 'Invalid Client ID format.' });
  if (!clientSecret || clientSecret.length < 8) return res.status(400).json({ error: 'Client Secret too short.' });
  if (!UUID_RE.test(subscriptionId)) return res.status(400).json({ error: 'Invalid Subscription ID format.' });

  try {
    await validateCredentials({ tenantId, clientId, clientSecret, subscriptionId });
  } catch (err) {
    console.error('[auth/connect] Validation failed:', err.message || 'Unknown error');
    const msg = err.message || '';
    if (msg.includes('AADSTS'))  return res.status(401).json({ error: 'Azure rejected the credentials. Verify Tenant ID, Client ID, and Secret.' });
    if (msg.includes('network')) return res.status(502).json({ error: 'Could not reach Azure. Check network connectivity.' });
    return res.status(401).json({ error: 'Credential validation failed: ' + msg });
  }

  req.session.azureCreds = { tenantId, clientId, clientSecret, subscriptionId };
  res.json({ ok: true });
});

// GET /api/auth/dev-creds
// Returns .env credentials to auto-fill the form during local development.
// Disabled in production.
router.get('/dev-creds', (req, res) => {
  if (process.env.NODE_ENV === 'production') return res.status(404).end();
  res.json({
    tenantId:       process.env.AZURE_TENANT_ID       || '',
    clientId:       process.env.AZURE_CLIENT_ID       || '',
    clientSecret:   process.env.AZURE_CLIENT_SECRET   || '',
    subscriptionId: process.env.AZURE_SUBSCRIPTION_ID || '',
  });
});

// POST /api/auth/disconnect
// Destroys the server-side session, clearing all stored credentials.
// The client should redirect to / after calling this.
router.post('/disconnect', (req, res) => {
  req.session.destroy();
  res.json({ ok: true });
});

module.exports = router;
