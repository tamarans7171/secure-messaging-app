process.env.NODE_ENV = 'test';
jest.setTimeout(20000);
const { encryptAtRest, decryptAtRest } = require('../crypto-utils');

test('AES-GCM encrypt/decrypt round trip', () => {
  const text = 'secret payload for at-rest test';
  const sealed = encryptAtRest(text);
  const out = decryptAtRest(sealed.iv, sealed.ciphertext, sealed.authTag);
  expect(out).toBe(text);
});
