const { randomBytes, createCipheriv, createDecipheriv } = require('crypto');

function getAesKeyFromEnv() {
  const base64 = process.env.MESSAGE_AES_KEY;
  if (!base64) return null;
  const buf = Buffer.from(base64, 'base64');
  return buf.length === 32 ? buf : null;
}

const AES_KEY = getAesKeyFromEnv() || randomBytes(32);

function encryptAtRest(plaintext) {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', AES_KEY, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return {
    iv: iv.toString('base64'),
    ciphertext: ciphertext.toString('base64'),
    authTag: authTag.toString('base64')
  };
}

function decryptAtRest(ivB64, ctB64, tagB64) {
  const iv = Buffer.from(ivB64, 'base64');
  const ciphertext = Buffer.from(ctB64, 'base64');
  const authTag = Buffer.from(tagB64, 'base64');
  const decipher = createDecipheriv('aes-256-gcm', AES_KEY, iv);
  decipher.setAuthTag(authTag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
}

module.exports = { encryptAtRest, decryptAtRest };
