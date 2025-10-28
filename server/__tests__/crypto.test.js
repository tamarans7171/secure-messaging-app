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


