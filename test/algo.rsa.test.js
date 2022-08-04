import C from '../src/index';

beforeAll(async () => {
  await C.algo.RSA.loadWasm();
});

describe('algo-rsa-test', () => {
  test('testRSAKeyPair', () => {
    expect(C.RSA.getKeyContent('private', 'pem')).not.toBe('');
  });

  test('generateRSAKeyPair', async () => {
    expect(C.RSA.getKeyContent('private', 'pem')).not.toBe('');
  });

  test('generateMultipleRSAKeyPairs', async () => {
    C.RSA.updateRsaKey(2048);
    expect(C.RSA.getKeyContent('private', 'pem')).not.toBe('');
  });

  test('encryptAndDecrypt', async () => {
    const msg = 'testMessage';
    const encrypted = C.RSA.encrypt(msg);
    const decrypted = C.RSA.decrypt(encrypted);
    expect(new TextDecoder().decode(decrypted)).toBe(msg);
  });

  test('encryptAndDecryptWithPKCS1V15', async () => {
    const msg = 'testMessage';
    const privateKey = C.RSA.getKeyContent('private', 'pem');
    const encrypted = C.RSA.encrypt(msg, privateKey, false, {encryptPadding: 'PKCS1V15'});
    const decrypted = C.RSA.decrypt(encrypted, privateKey, false, {encryptPadding: 'PKCS1V15'});
    expect(new TextDecoder().decode(decrypted)).toBe(msg);
  });

  test('encryptAndDecryptWithOAEP', async () => {
    const msg = 'testMessage';
    const privateKey = C.RSA.getKeyContent('private', 'pem');
    const encrypted = C.RSA.encrypt(msg, privateKey, false, {encryptPadding: 'OAEP'});
    const decrypted = C.RSA.decrypt(encrypted, privateKey, false, {encryptPadding: 'OAEP'});
    expect(new TextDecoder().decode(decrypted)).toBe(msg);
  });

  test('encryptAndDecryptWithErrorPadding', async () => {
    const msg = 'testMessage';
    const privateKey = C.RSA.getKeyContent('private', 'pem');
    const encrypted = C.RSA.encrypt(msg, privateKey, false, {encryptPadding: 'ErrorPadding'});
    const decrypted = C.RSA.decrypt(encrypted, privateKey, false, {encryptPadding: 'ErrorPadding'});
    expect(new TextDecoder().decode(decrypted)).toBe(msg);
  });

  test('encryptWithPKCS1V15AndOAEP', async () => {
    const msg = 'testMessage';
    const privateKey = C.RSA.getKeyContent('private', 'pem');
    const PKCSEncrypted = C.RSA.encrypt(msg, privateKey, false, {encryptPadding: 'PKCS1V15'});
    const OAEPDecrypted = C.RSA.decrypt(PKCSEncrypted, privateKey, false, {encryptPadding: 'OAEP'});
    expect(OAEPDecrypted).toBeNull();

    const OAEPEncrypted = C.RSA.encrypt(msg, privateKey, false, {encryptPadding: 'OAEP'});
    const PKCSDecrypted = C.RSA.decrypt(OAEPEncrypted, privateKey, false, {encryptPadding: 'PKCS1V15'});
    expect(PKCSDecrypted).toBeNull();
  });

  // TODO: add tests for sign, verify, generateKeyFile and getKeyType
});
