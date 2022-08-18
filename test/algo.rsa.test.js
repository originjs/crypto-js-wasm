import C from '../src/index';

beforeAll(async () => {
  await C.loadAllWasm();
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
    const encrypted = C.RSA.encrypt(msg, {encryptPadding: 'PKCS1V15',});
    const decrypted = C.RSA.decrypt(encrypted, {encryptPadding: 'PKCS1V15',});
    expect(new TextDecoder().decode(decrypted)).toBe(msg);
  });

  test('encryptAndDecryptWithOAEP', () => {
    const msg = 'testMessage';
    const encrypted = C.RSA.encrypt(msg, {encryptPadding: 'OAEP',});
    const decrypted = C.RSA.decrypt(encrypted, {encryptPadding: 'OAEP',});
    expect(new TextDecoder().decode(decrypted)).toBe(msg);
  });

  test('encryptWithErrorPadding', () => {
    // error is expected, ignore console error print
    const consoleErrorFun = console.error;
    console.error = () => {};

    const msg = 'testMessage';
    expect(() => {
      C.RSA.encrypt(msg, {encryptPadding: 'ErrorPadding',});
    }).toThrow();

    // recover console error print
    console.error = consoleErrorFun;
  });

  test('encryptWithPKCS1V15AndOAEP', () => {
    // error is expected, ignore console error print
    const consoleErrorFun = console.error;
    console.error = () => {};

    const msg = 'testMessage';
    const PKCSEncrypted = C.RSA.encrypt(msg, {encryptPadding: 'PKCS1V15',});
    const OAEPDecrypted = C.RSA.decrypt(PKCSEncrypted, {encryptPadding: 'OAEP',});
    expect(OAEPDecrypted).toBeNull();

    const OAEPEncrypted = C.RSA.encrypt(msg, {encryptPadding: 'OAEP',});
    const PKCSDecrypted = C.RSA.decrypt(OAEPEncrypted, {encryptPadding: 'PKCS1V15',});
    expect(PKCSDecrypted).toBeNull();

    // recover console error print
    console.error = consoleErrorFun;
  });

  test('signDigestOfMd5WithPKCS1V15', () => {
    const message = 'test message';
    const digest = C.RSA.digest(message, {hashAlgo: 'MD5',});
    C.RSA.updateConfig({signPadding: 'PKCS1V15',});
    const signature = C.RSA.sign(digest);
    // const signature = C.RSA.sign(digest, {signPadding: 'PKCS1V15',});
    expect(C.RSA.verify(digest, signature)).toBe(true);
  });

  test('signDigestOfSha1WithPKCS1V15', () => {
    const message = 'test message';
    const digest = C.RSA.digest(message, {hashAlgo: 'SHA1',});
    const signature = C.RSA.sign(digest, {signPadding: 'PKCS1V15',});
    expect(C.RSA.verify(digest, signature)).toBe(true);
  });

  test('signDigestOfSha224WithPKCS1V15', () => {
    const message = 'test message';
    const digest = C.RSA.digest(message, {hashAlgo: 'SHA224',});
    const signature = C.RSA.sign(digest, {signPadding: 'PKCS1V15',});
    expect(C.RSA.verify(digest, signature)).toBe(true);
  });

  test('signDigestOfSha256WithPKCS1V15', () => {
    const message = 'test message';
    const digest = C.RSA.digest(message, {hashAlgo: 'SHA256',});
    const signature = C.RSA.sign(digest, {signPadding: 'PKCS1V15',});
    expect(C.RSA.verify(digest, signature)).toBe(true);
  });

  test('signDigestOfSha384WithPKCS1V15', () => {
    const message = 'test message';
    const digest = C.RSA.digest(message, {hashAlgo: 'SHA384',});
    const signature = C.RSA.sign(digest, {signPadding: 'PKCS1V15',});
    expect(C.RSA.verify(digest, signature)).toBe(true);
  });

  test('signDigestOfSha512WithPKCS1V15', () => {
    const message = 'test message';
    const digest = C.RSA.digest(message, {hashAlgo: 'SHA512',});
    const signature = C.RSA.sign(digest, {signPadding: 'PKCS1V15',});
    expect(C.RSA.verify(digest, signature)).toBe(true);
  });

  test('signDigestOfRIPEMD160WithPKCS1V15', () => {
    const message = 'test message';
    const digest = C.RSA.digest(message, {hashAlgo: 'RIPEMD160',});
    const signature = C.RSA.sign(digest, {signPadding: 'PKCS1V15',});
    expect(C.RSA.verify(digest, signature)).toBe(true);
  });

  test('signDigestOfMd5WithPSS', () => {
    const message = 'test message';
    const digest = C.RSA.digest(message, {hashAlgo: 'MD5',});
    const signature = C.RSA.sign(digest);
    expect(C.RSA.verify(digest, signature)).toBe(true);
  });

  test('signDigestOfSha1WithPSS', () => {
    const message = 'test message';
    const digest = C.RSA.digest(message, {hashAlgo: 'SHA1',});
    const signature = C.RSA.sign(digest);
    expect(C.RSA.verify(digest, signature)).toBe(true);
  });

  test('signDigestOfSha224WithPSS', () => {
    const message = 'test message';
    const digest = C.RSA.digest(message, {hashAlgo: 'SHA224',});
    const signature = C.RSA.sign(digest);
    expect(C.RSA.verify(digest, signature)).toBe(true);
  });

  test('signDigestOfSha256WithPKCS1V15', () => {
    const message = 'test message';
    const digest = C.RSA.digest(message, {hashAlgo: 'SHA256',});
    const signature = C.RSA.sign(digest);
    expect(C.RSA.verify(digest, signature)).toBe(true);
  });

  test('signDigestOfSha384WithPKCS1V15', () => {
    const message = 'test message';
    const digest = C.RSA.digest(message, {hashAlgo: 'SHA384',});
    const signature = C.RSA.sign(digest);
    expect(C.RSA.verify(digest, signature)).toBe(true);
  });

  test('signDigestOfSha512WithPKCS1V15', () => {
    const message = 'test message';
    const digest = C.RSA.digest(message, {hashAlgo: 'SHA512',});
    const signature = C.RSA.sign(digest);
    expect(C.RSA.verify(digest, signature)).toBe(true);
  });

  test('signDigestOfRIPEMD160WithPKCS1V15', () => {
    const message = 'test message';
    const digest = C.RSA.digest(message, {hashAlgo: 'RIPEMD160',});
    const signature = C.RSA.sign(digest);
    expect(C.RSA.verify(digest, signature)).toBe(true);
  });

  // TODO: add tests for sign, verify, generateKeyFile and getKeyType
});
