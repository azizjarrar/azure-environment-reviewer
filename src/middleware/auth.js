const { decrypt }      = require('../utils/encryption');
const AzureCredential  = require('../models/AzureCredential');

/**
 * Middleware — requires a logged-in user with at least one active Azure credential.
 * Attaches decrypted creds to req.azureCreds for downstream handlers.
 */
async function requireSession(req, res, next) {
  if (!req.session?.userId)
    return res.status(401).json({ error: 'Please sign in.' });

  const cred = await AzureCredential.findOne({ userId: req.session.userId, isActive: true });
  if (!cred)
    return res.status(400).json({ error: 'No active Azure credentials. Add credentials in Settings first.' });

  req.azureCreds = {
    tenantId:       cred.tenantId,
    clientId:       cred.clientId,
    clientSecret:   decrypt(cred.clientSecretEnc),
    subscriptionId: cred.subscriptionId,
    label:          cred.label,
  };
  next();
}

module.exports = { requireSession };
