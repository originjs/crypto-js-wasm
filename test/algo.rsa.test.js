import C from '../src/index';
import fs from 'fs';

beforeAll(async () => {
  await C.RSA.loadWasm();
});

describe('algo-rsa-test', () => {
  test('generateRSAKeyPair', () => {
    C.RSA.resetConfig();
    expect(C.RSA.getKeyContent('private', 'pem')).not.toBe('');
  });

  test('generateMultipleRSAKeyPairs', () => {
    C.RSA.resetConfig();
    C.RSA.updateRsaKey(2048);
    expect(C.RSA.getKeyContent('private', 'pem')).not.toBe('');
  });

  test('throwErrorIfNoPrivateKeyIsSpecified', () => {
    C.RSA.resetConfig();
    const publicKeyContent = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxKTXrXDK/7OpBZEX5pwr
sOrHujHx4dXxjkVCHJJnRqmMWvix4cHTJig5AFdZ3NH6xoIX2geaZV2uShNeExpb
reSEuFrMfGYflndeuoaCQAJyzxr4fYDQTRoQfWzqMQ5b3TBZdbPhPUMSGAGIJH5R
LyLirx7EA/S2CtedWMa3QStcIkFA6hHsqOyJGqR06TerraWCysqNDegmYsWO+1co
WuFrrlrBddfQck2RAWOax8k5rAUfO5nkyzscsSPxtlc7mGhlN5Z5i3smuNyekYlQ
2tC9unqj0n9Pj/dgVdcqBjz1VnHWGOMvL1vn1miX3DH5d3Z1kd2/Q2w5ghVE8I65
uwIDAQAB
-----END PUBLIC KEY-----`;
    C.RSA.updateRsaKey(publicKeyContent, true);
    // generateKeyFile for pairs and private should throw
    expect(() => {
      C.RSA.generateKeyFile('pairs');
    }).toThrow();
    expect(() => {
      C.RSA.generateKeyFile('private');
    }).toThrow();

    // getKeyContent for private should throw
    expect(() => {
      C.RSA.getKeyContent('private', 'pem');
    }).toThrow();

    const message = 'test message';
    const encrypted = C.RSA.encrypt(message, {
      key: publicKeyContent,
      isPublicKey: true
    });
    // decrypt should throw
    expect(() => {
      C.RSA.decrypt(encrypted);
    }).toThrow();

    const digest = C.RSA.digest(message);
    // sign should throw
    expect(() => {
      C.RSA.sign(digest);
    }).toThrow();
  });

  test('encryptAndDecrypt', () => {
    C.RSA.resetConfig();
    const msg = 'testMessage';
    const encrypted = C.RSA.encrypt(msg);
    const decrypted = C.RSA.decrypt(encrypted);
    expect(new TextDecoder().decode(decrypted)).toBe(msg);
  });

  test('encryptAndDecryptWithPKCS1V15', () => {
    C.RSA.resetConfig();
    const msg = 'testMessage';
    const encrypted = C.RSA.encrypt(msg, { encryptPadding: 'pkcs1v15' });
    const decrypted = C.RSA.decrypt(encrypted, { encryptPadding: 'pkcs1v15' });
    expect(new TextDecoder().decode(decrypted)).toBe(msg);
  });

  test('encryptAndDecryptWithOAEP', () => {
    C.RSA.resetConfig();
    const msg = 'testMessage';
    const encrypted = C.RSA.encrypt(msg, { encryptPadding: 'oaep' });
    const decrypted = C.RSA.decrypt(encrypted, { encryptPadding: 'oaep' });
    expect(new TextDecoder().decode(decrypted)).toBe(msg);
  });

  test('encryptWithErrorPadding', () => {
    C.RSA.resetConfig();

    const msg = 'testMessage';
    expect(() => {
      C.RSA.encrypt(msg, { encryptPadding: 'ErrorPadding' });
    }).toThrow();
  });

  test('encryptWithPKCS1V15AndOAEP', () => {
    C.RSA.resetConfig();
    // error is expected, ignore console error print
    const consoleErrorFun = console.error;
    console.error = () => {};

    const msg = 'testMessage';
    const PKCSEncrypted = C.RSA.encrypt(msg, { encryptPadding: 'pkcs1v15' });
    const OAEPDecrypted = C.RSA.decrypt(PKCSEncrypted, { encryptPadding: 'oaep' });
    expect(OAEPDecrypted).toBeNull();

    const OAEPEncrypted = C.RSA.encrypt(msg, { encryptPadding: 'oaep' });
    const PKCSDecrypted = C.RSA.decrypt(OAEPEncrypted, { encryptPadding: 'pkcs1v15' });
    expect(PKCSDecrypted).toBeNull();

    // recover console error print
    console.error = consoleErrorFun;
  });

  test('encryptTooLongMessage', () => {
    C.RSA.resetConfig();

    const msgOAEPTooLong = new Uint8Array(191);
    expect(() => {
      C.RSA.encrypt(msgOAEPTooLong, { encryptPadding: 'oaep' });
    }).toThrow();

    const msgOAEPMD5TooLong = new Uint8Array(223);
    expect(() => {
      C.RSA.encrypt(msgOAEPMD5TooLong, { encryptPadding: 'oaep', hashAlgo: 'md5' });
    }).toThrow();

    const msgPKCS1V15TooLong = new Uint8Array(246);
    expect(() => {
      C.RSA.encrypt(msgPKCS1V15TooLong, { encryptPadding: 'pkcs1v15' });
    }).toThrow();
  });

  test('signTooLongDigest', () => {
    C.RSA.resetConfig();
    C.RSA.updateRsaKey(1024);

    // error is expected, ignore console error print
    const consoleErrorFun = console.error;
    console.error = () => {};

    const msg = 'test message';
    const digestSha512 = C.RSA.digest(msg, { hashAlgo: 'sha512' });
    expect(() => {
      C.RSA.sign(digestSha512);
    }).toThrow();

    // recover console error print
    console.error = consoleErrorFun;
  });

  test('signDigestOfMd5WithPKCS1V15', () => {
    C.RSA.resetConfig();
    const message = 'test message';
    const digest = C.RSA.digest(message, { hashAlgo: 'md5' });
    const signature = C.RSA.sign(digest, { signPadding: 'pkcs1v15' });
    expect(C.RSA.verify(digest, signature)).toBe(true);

    const errorDigest = C.RSA.digest('another message', { hashAlgo: 'md5' });
    expect(C.RSA.verify(errorDigest, signature)).toBe(false);
  });

  test('signDigestOfSha1WithPKCS1V15', () => {
    C.RSA.resetConfig();
    const message = 'test message';
    const digest = C.RSA.digest(message, { hashAlgo: 'sha1' });
    const signature = C.RSA.sign(digest, { signPadding: 'pkcs1v15' });
    expect(C.RSA.verify(digest, signature)).toBe(true);
  });

  test('signDigestOfSha224WithPKCS1V15', () => {
    C.RSA.resetConfig();
    const message = 'test message';
    const digest = C.RSA.digest(message, { hashAlgo: 'sha224' });
    const signature = C.RSA.sign(digest, { signPadding: 'pkcs1v15' });
    expect(C.RSA.verify(digest, signature)).toBe(true);
  });

  test('signDigestOfSha256WithPKCS1V15', () => {
    C.RSA.resetConfig();
    const message = 'test message';
    const digest = C.RSA.digest(message, { hashAlgo: 'sha256' });
    const signature = C.RSA.sign(digest, { signPadding: 'pkcs1v15' });
    expect(C.RSA.verify(digest, signature)).toBe(true);
  });

  test('signDigestOfSha384WithPKCS1V15', () => {
    C.RSA.resetConfig();
    const message = 'test message';
    const digest = C.RSA.digest(message, { hashAlgo: 'sha384' });
    const signature = C.RSA.sign(digest, { signPadding: 'pkcs1v15' });
    expect(C.RSA.verify(digest, signature)).toBe(true);
  });

  test('signDigestOfSha512WithPKCS1V15', () => {
    C.RSA.resetConfig();
    const message = 'test message';
    const digest = C.RSA.digest(message, { hashAlgo: 'sha512' });
    const signature = C.RSA.sign(digest, { signPadding: 'pkcs1v15' });
    expect(C.RSA.verify(digest, signature)).toBe(true);
  });

  test('signDigestOfRIPEMD160WithPKCS1V15', () => {
    C.RSA.resetConfig();
    const message = 'test message';
    const digest = C.RSA.digest(message, { hashAlgo: 'RIPEMD160' });
    const signature = C.RSA.sign(digest, { signPadding: 'pkcs1v15' });
    expect(C.RSA.verify(digest, signature)).toBe(true);
  });

  test('signDigestOfMd5WithPSS', () => {
    C.RSA.resetConfig();
    const message = 'test message';
    const digest = C.RSA.digest(message, { hashAlgo: 'md5' });
    const signature = C.RSA.sign(digest);
    expect(C.RSA.verify(digest, signature)).toBe(true);
  });

  test('signDigestOfSha1WithPSS', () => {
    C.RSA.resetConfig();
    const message = 'test message';
    const digest = C.RSA.digest(message, { hashAlgo: 'sha1' });
    const signature = C.RSA.sign(digest);
    expect(C.RSA.verify(digest, signature)).toBe(true);
  });

  test('signDigestOfSha224WithPSS', () => {
    C.RSA.resetConfig();
    const message = 'test message';
    const digest = C.RSA.digest(message, { hashAlgo: 'sha224' });
    const signature = C.RSA.sign(digest);
    expect(C.RSA.verify(digest, signature)).toBe(true);
  });

  test('signDigestOfSha256WithPSS', () => {
    C.RSA.resetConfig();
    const message = 'test message';
    const digest = C.RSA.digest(message, { hashAlgo: 'sha256' });
    const signature = C.RSA.sign(digest);
    expect(C.RSA.verify(digest, signature)).toBe(true);
  });

  test('signDigestOfSha384WithPSS', () => {
    C.RSA.resetConfig();
    const message = 'test message';
    const digest = C.RSA.digest(message, { hashAlgo: 'sha384' });
    const signature = C.RSA.sign(digest);
    expect(C.RSA.verify(digest, signature)).toBe(true);
  });

  test('signDigestOfSha512WithPSS', () => {
    C.RSA.resetConfig();
    const message = 'test message';
    const digest = C.RSA.digest(message, { hashAlgo: 'sha512' });
    const signature = C.RSA.sign(digest);
    expect(C.RSA.verify(digest, signature)).toBe(true);
  });

  test('signDigestOfRipemd160WithPSS', () => {
    C.RSA.resetConfig();
    const message = 'test message';
    const digest = C.RSA.digest(message, { hashAlgo: 'ripemd160' });
    const signature = C.RSA.sign(digest);
    expect(C.RSA.verify(digest, signature)).toBe(true);
  });

  test('testRSAAlgo', () => {
    const rsa = new C.algo.RSA();
    rsa.resetConfig();
    expect(rsa.getKeyContent('private', 'pem')).not.toBe('');

    // encrypt and decrypt
    const msg = 'testMessage';
    const encrypted = rsa.encrypt(msg);
    const decrypted = rsa.decrypt(encrypted);
    expect(new TextDecoder().decode(decrypted)).toBe(msg);

    // sign and verify
    const digest = rsa.digest(msg, { hashAlgo: 'md5' });
    const signature = rsa.sign(digest, { signPadding: 'pkcs1v15' });
    expect(rsa.verify(digest, signature)).toBe(true);
  });

  test('verifyDigestWithWrongPadding', () => {
    C.RSA.resetConfig();

    const message = 'testMessage';
    const digest = C.RSA.digest(message, { hashAlgo: 'ripemd160' });
    const signature = C.RSA.sign(digest, { signPadding: 'PSS' });
    expect(C.RSA.verify(digest, signature, { signPadding: 'pkcs1v15' })).toBe(false);
  });

  test('generatePrivateAndPublicKeyFile', () => {
    C.RSA.resetConfig();
    C.RSA.generateKeyFile('pairs');
    expect(fs.readFileSync('./keys/key_private.pem', { encoding: 'utf-8' }))
      .toMatch(/^-----BEGIN PRIVATE KEY-----/);
    expect(fs.readFileSync('./keys/key_public.pem', { encoding: 'utf-8' }))
      .toMatch(/^-----BEGIN PUBLIC KEY-----/);
    fs.rmdirSync('./keys', { recursive: true, force: true });
  });

  test('generatePrivateKeyFile', () => {
    C.RSA.resetConfig();
    C.RSA.generateKeyFile('private', 'pem', 'key');
    expect(fs.readFileSync('./keys/key.pem', { encoding: 'utf-8' }))
      .toMatch(/^-----BEGIN PRIVATE KEY-----/);
    fs.rmdirSync('./keys', { recursive: true, force: true });
  });

  test('generatePublicKeyFile', () => {
    C.RSA.resetConfig();
    C.RSA.generateKeyFile('public', 'pem', 'key');
    expect(fs.readFileSync('./keys/key.pem', { encoding: 'utf-8' }))
      .toMatch(/^-----BEGIN PUBLIC KEY-----/);
    fs.rmdirSync('./keys', { recursive: true, force: true });
  });

  test('getKeyTypeOfPrivateKey', () => {
    C.RSA.resetConfig();
    expect(C.RSA.getKeyType()).toBe('private');
  });

  test('getKeyTypeOfPublicKey', () => {
    C.RSA.resetConfig();
    C.RSA.generateKeyFile('public');
    C.RSA.updateRsaKey('./keys/key.pem', true);
    expect(C.RSA.getKeyType()).toBe('public');
    fs.rmdirSync('./keys', { recursive: true, force: true });
  });
});
