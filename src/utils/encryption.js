const crypto = require('crypto');

// Derive a stable 32-byte AES key from the secret so it stays consistent across restarts.
// scryptSync prevents the raw secret from being reversible even if the DB is compromised.
const ENCRYPTION_KEY = crypto.scryptSync(
  process.env.ENCRYPTION_KEY || process.env.SESSION_SECRET || 'dev-only-key-set-ENCRYPTION_KEY-in-env',
  'azure-review-cred-enc-v1',
  32
);

// AES-256-GCM authenticated encryption.
// Returns "ivHex:authTagHex:ciphertextHex" — all three pieces are needed to decrypt.
function encrypt(plaintext) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', ENCRYPTION_KEY, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return [iv.toString('hex'), authTag.toString('hex'), encrypted.toString('hex')].join(':');
}

function decrypt(encoded) {
  const [ivHex, authTagHex, encryptedHex] = encoded.split(':');
  const iv        = Buffer.from(ivHex, 'hex');
  const authTag   = Buffer.from(authTagHex, 'hex');
  const encrypted = Buffer.from(encryptedHex, 'hex');
  const decipher  = crypto.createDecipheriv('aes-256-gcm', ENCRYPTION_KEY, iv);
  decipher.setAuthTag(authTag);
  return decipher.update(encrypted, undefined, 'utf8') + decipher.final('utf8');
}

module.exports = { encrypt, decrypt };
