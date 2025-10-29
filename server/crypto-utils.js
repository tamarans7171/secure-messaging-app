const { randomBytes, createCipheriv, createDecipheriv } = require('crypto');

// AES-256-GCM helpers for encrypting/decrypting messages at rest.
// Exports functions that accept an optional base64 key (for testing).

function _getKey(keyBase64) {
  const envKey = process.env.MESSAGE_AES_KEY;
  const b64 = keyBase64 || envKey;
  if (!b64) return null; // caller may handle volatile key
  const buf = Buffer.from(b64, 'base64');
  if (buf.length !== 32) throw new Error('MESSAGE_AES_KEY must be base64 of 32 bytes');
  return buf;
}

function encryptAtRest(plaintext, keyBase64) {
  const key = _getKey(keyBase64) || randomBytes(32);
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return {
    iv: iv.toString('base64'),
    ciphertext: ciphertext.toString('base64'),
    authTag: authTag.toString('base64')
  };
}

function decryptAtRest(ivB64, ctB64, tagB64, keyBase64) {
  const key = _getKey(keyBase64);
  if (!key) throw new Error('No MESSAGE_AES_KEY available to decrypt');
  const iv = Buffer.from(ivB64, 'base64');
  const ciphertext = Buffer.from(ctB64, 'base64');
  const authTag = Buffer.from(tagB64, 'base64');
  const decipher = createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(authTag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
}

module.exports = { encryptAtRest, decryptAtRest };
