const { encryptAtRest, decryptAtRest } = require('../crypto-utils');

describe('AES-GCM encrypt/decrypt', () => {
  const key = Buffer.from('a'.repeat(32)).toString('base64'); // deterministic test key

  test('roundtrip with correct key', () => {
    const plaintext = 'hello secure world';
    const sealed = encryptAtRest(plaintext, key);
    const out = decryptAtRest(sealed.iv, sealed.ciphertext, sealed.authTag, key);
    expect(out).toBe(plaintext);
  });

  test('decrypt fails with wrong key', () => {
    const plaintext = 'top secret';
    const sealed = encryptAtRest(plaintext, key);
    const wrongKey = Buffer.from('b'.repeat(32)).toString('base64');
    expect(() => decryptAtRest(sealed.iv, sealed.ciphertext, sealed.authTag, wrongKey)).toThrow();
  });
});
const { createCipheriv, createDecipheriv, randomBytes } = require('crypto');

function roundTripAesGcm(plaintext) {
  const key = randomBytes(32);
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();

  const decipher = createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  const out = Buffer.concat([decipher.update(ct), decipher.final()]).toString('utf8');
  return out;
}

test('AES-GCM round trip', () => {
  const msg = 'hello secure world';
  const out = roundTripAesGcm(msg);
  expect(out).toBe(msg);
});


