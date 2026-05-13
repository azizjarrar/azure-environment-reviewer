const express         = require('express');
const router          = express.Router();
const AzureCredential = require('../models/AzureCredential');
const { encrypt, decrypt } = require('../utils/encryption');
const { validateCredentials } = require('../utils/azureClient');

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function requireUser(req, res, next) {
  if (!req.session?.userId) return res.status(401).json({ error: 'Please sign in.' });
  next();
}

function validateFields({ tenantId, clientId, clientSecret, subscriptionId }) {
  if (!UUID_RE.test(tenantId))                      return 'Invalid Tenant ID format.';
  if (!UUID_RE.test(clientId))                      return 'Invalid Client ID format.';
  if (!clientSecret || clientSecret.length < 8)     return 'Client Secret too short.';
  if (!UUID_RE.test(subscriptionId))                return 'Invalid Subscription ID format.';
  return null;
}

// GET /api/credentials — list all credential sets for the signed-in user
router.get('/', requireUser, async (req, res) => {
  const creds = await AzureCredential.find({ userId: req.session.userId })
    .select('-clientSecretEnc')
    .sort('-createdAt');
  res.json({ credentials: creds });
});

// POST /api/credentials — validate against Azure, then save encrypted
router.post('/', requireUser, async (req, res) => {
  const { label, tenantId, clientId, clientSecret, subscriptionId } = req.body || {};
  const err = validateFields({ tenantId, clientId, clientSecret, subscriptionId });
  if (err) return res.status(400).json({ error: err });

  try {
    await validateCredentials({ tenantId, clientId, clientSecret, subscriptionId });
  } catch (e) {
    const msg = e.message || '';
    if (msg.includes('AADSTS'))
      return res.status(401).json({ error: 'Azure rejected the credentials. Check Tenant ID, Client ID, and Secret.' });
    return res.status(401).json({ error: 'Credential validation failed: ' + msg });
  }

  // First credential for this user is set active automatically.
  const count = await AzureCredential.countDocuments({ userId: req.session.userId });
  const isActive = count === 0;

  const cred = await AzureCredential.create({
    userId: req.session.userId,
    label: (label || 'Default').trim(),
    tenantId, clientId,
    clientSecretEnc: encrypt(clientSecret),
    subscriptionId, isActive,
  });

  res.status(201).json({ ok: true, id: cred._id });
});

// PUT /api/credentials/:id — update label or credentials (re-validates if secret changes)
router.put('/:id', requireUser, async (req, res) => {
  const cred = await AzureCredential.findOne({ _id: req.params.id, userId: req.session.userId });
  if (!cred) return res.status(404).json({ error: 'Credential not found.' });

  const { label, tenantId, clientId, clientSecret, subscriptionId } = req.body || {};

  if (label !== undefined)          cred.label          = label.trim();
  if (tenantId !== undefined)       cred.tenantId        = tenantId;
  if (clientId !== undefined)       cred.clientId        = clientId;
  if (subscriptionId !== undefined) cred.subscriptionId  = subscriptionId;
  if (clientSecret) {
    if (clientSecret.length < 8)
      return res.status(400).json({ error: 'Client Secret too short.' });
    cred.clientSecretEnc = encrypt(clientSecret);
  }

  await cred.save();
  res.json({ ok: true });
});

// DELETE /api/credentials/:id
router.delete('/:id', requireUser, async (req, res) => {
  const result = await AzureCredential.deleteOne({ _id: req.params.id, userId: req.session.userId });
  if (result.deletedCount === 0) return res.status(404).json({ error: 'Credential not found.' });
  res.json({ ok: true });
});

// POST /api/credentials/:id/activate — set one credential as active for reviews
router.post('/:id/activate', requireUser, async (req, res) => {
  const cred = await AzureCredential.findOne({ _id: req.params.id, userId: req.session.userId });
  if (!cred) return res.status(404).json({ error: 'Credential not found.' });

  await AzureCredential.updateMany({ userId: req.session.userId }, { isActive: false });
  cred.isActive = true;
  await cred.save();

  res.json({ ok: true });
});

// POST /api/credentials/:id/test — re-test stored credentials against Azure
router.post('/:id/test', requireUser, async (req, res) => {
  const cred = await AzureCredential.findOne({ _id: req.params.id, userId: req.session.userId });
  if (!cred) return res.status(404).json({ error: 'Credential not found.' });

  try {
    await validateCredentials({
      tenantId:       cred.tenantId,
      clientId:       cred.clientId,
      clientSecret:   decrypt(cred.clientSecretEnc),
      subscriptionId: cred.subscriptionId,
    });
    res.json({ ok: true, valid: true });
  } catch (e) {
    res.json({ ok: true, valid: false, error: e.message });
  }
});

module.exports = router;
