import C from '../src/index';

beforeAll(async () => {
  await C.algo.RSA.loadWasm();
  await C.SHA512.loadWasm();
  await C.SHA256.loadWasm();
});

describe('algo-rsa-test', () => {
  test('testRSAKeyPair', () => {
    expect(C.RSA.getKeyContent('private', 'pem')).not.toBe('');
  });

  test('generateRSAKeyPair', () => {
    expect(C.RSA.getKeyContent('private', 'pem')).not.toBe('');
  });

  test('generateMultipleRSAKeyPairs', () => {
    C.RSA.updateRsaKey(2048);
    expect(C.RSA.getKeyContent('private', 'pem')).not.toBe('');
  });

  test('encryptAndDecrypt', () => {
    const msg = 'testMessage';
    const encrypted = C.RSA.encrypt(msg);
    const decrypted = C.RSA.decrypt(encrypted);
    expect(new TextDecoder().decode(decrypted)).toBe(msg);
  });

  test('encryptAndDecryptWithPKCS1V15', () => {
    const msg = 'testMessage';
    const privateKey = C.RSA.getKeyContent('private', 'pem');
    const encrypted = C.RSA.encrypt(msg, privateKey, false, {encryptPadding: 'PKCS1V15',});
    const decrypted = C.RSA.decrypt(encrypted, privateKey, false, {encryptPadding: 'PKCS1V15',});
    expect(new TextDecoder().decode(decrypted)).toBe(msg);
  });

  test('encryptAndDecryptWithOAEP', () => {
    const msg = 'testMessage';
    const privateKey = C.RSA.getKeyContent('private', 'pem');
    const encrypted = C.RSA.encrypt(msg, privateKey, false, {encryptPadding: 'OAEP',});
    const decrypted = C.RSA.decrypt(encrypted, privateKey, false, {encryptPadding: 'OAEP',});
    expect(new TextDecoder().decode(decrypted)).toBe(msg);
  });

  test('encryptAndDecryptWithErrorPadding', () => {
    const msg = 'testMessage';
    const privateKey = C.RSA.getKeyContent('private', 'pem');
    const encrypted = C.RSA.encrypt(msg, privateKey, false, {encryptPadding: 'ErrorPadding',});
    const decrypted = C.RSA.decrypt(encrypted, privateKey, false, {encryptPadding: 'ErrorPadding',});
    expect(new TextDecoder().decode(decrypted)).toBe(msg);
  });

  test('encryptWithPKCS1V15AndOAEP', () => {
    // error is expected, ignore console error print
    const consoleErrorFun = console.error;
    console.error = () => {};

    const msg = 'testMessage';
    const privateKey = C.RSA.getKeyContent('private', 'pem');
    const PKCSEncrypted = C.RSA.encrypt(msg, privateKey, false, {encryptPadding: 'PKCS1V15',});
    const OAEPDecrypted = C.RSA.decrypt(PKCSEncrypted, privateKey, false, {encryptPadding: 'OAEP',});
    expect(OAEPDecrypted).toBeNull();

    const OAEPEncrypted = C.RSA.encrypt(msg, privateKey, false, {encryptPadding: 'OAEP',});
    const PKCSDecrypted = C.RSA.decrypt(OAEPEncrypted, privateKey, false, {encryptPadding: 'PKCS1V15',});
    expect(PKCSDecrypted).toBeNull();

    // recover console error print
    console.error = consoleErrorFun;
  });

  test('signDigestOfSha256WithPKCS1V15', () => {
    const message = 'test message';
    const digestWords = C.SHA256(message);
    const digestUint32Array = new Uint32Array(digestWords.words);
    const digest = new Uint8Array(digestUint32Array.buffer);
    const signature = C.RSA.sign(digest);
    expect(C.RSA.verify(digest, signature)).toBe(true);
  });

  test('signDigestOfSha256WithPSS', () => {
    const message = 'test message';
    const digestWords = C.SHA256(message);
    const digestUint32Array = new Uint32Array(digestWords.words);
    const digest = new Uint8Array(digestUint32Array.buffer);
    C.RSA.updateConfig({signPadding: 'PSS',});
    const signature = C.RSA.sign(digest);
    expect(C.RSA.verify(digest, signature)).toBe(true);
  });

  test('signDigestOfSha3WithPSS', () => {
    // failint
    const message = 'test message';
    const digestWords = C.SHA512(message);
    const digestUint32Array = new Uint32Array(digestWords.words);
    const digest = new Uint8Array(digestUint32Array.buffer);
    C.RSA.updateConfig({signPadding: 'PSS',});
    const signature = C.RSA.sign(digest);
    expect(C.RSA.verify(digest, signature)).toBe(true);
  });

  // TODO: add tests for sign, verify, generateKeyFile and getKeyType
});
