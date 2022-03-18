import C from '../src/index';

let data = {};
beforeAll(async () => {
  data.saltA = C.enc.Hex.parse('AA00000000000000');
  data.saltB = C.enc.Hex.parse('BB00000000000000');
  await C.AES.loadWasm();
  await C.SHA1.loadWasm();
  await C.SHA224.loadWasm();
  await C.SHA256.loadWasm();
  await C.SHA384.loadWasm();
  await C.SHA512.loadWasm();
});

describe('config-test', () => {
  test('testEncrypt', () => {
    expect(C.AES.encrypt('Test', 'Pass', { salt: data.saltA }).toString()).toBe(C.AES.encrypt('Test', 'Pass', { salt: data.saltA }).toString());
    expect(C.AES.encrypt('Test', 'Pass', { salt: data.saltA }).toString()).not.toBe(C.AES.encrypt('Test', 'Pass', { salt: data.saltB }).toString());
  });

  test('testDecrypt', () => {
    const encryptedA = C.AES.encrypt('Test', 'Pass', { salt: data.saltA });
    const encryptedB = C.AES.encrypt('Test', 'Pass', { salt: data.saltB });
    expect(C.AES.decrypt(encryptedA, 'Pass').toString(C.enc.Utf8)).toBe('Test');
    expect(C.AES.decrypt(encryptedB, 'Pass').toString(C.enc.Utf8)).toBe('Test');
  });

  test('testCustomKDFHasher', () => {
    //SHA1
    let encryptedSHA1 = C.AES.encrypt('Test', 'Pass', { salt: data.saltA, hasher: C.algo.SHA1}).toString();
    expect(C.AES.decrypt(encryptedSHA1, 'Pass', { hasher: C.algo.SHA1}).toString(C.enc.Utf8)).toBe('Test');

    //SHA256
    let encryptedSHA256 = C.AES.encrypt('Test', 'Pass', { salt: data.saltA, hasher: C.algo.SHA256}).toString();
    expect(C.AES.decrypt(encryptedSHA256, 'Pass', { hasher: C.algo.SHA256}).toString(C.enc.Utf8)).toBe('Test');

    //SHA512
    let encryptedSHA512 = C.AES.encrypt('Test', 'Pass', { salt: data.saltA, hasher: C.algo.SHA512}).toString();
    expect(C.AES.decrypt(encryptedSHA512, 'Pass', { hasher: C.algo.SHA512}).toString(C.enc.Utf8)).toBe('Test');

    //Default: MD5
    let encryptedDefault = C.AES.encrypt('Test', 'Pass', { salt: data.saltA }).toString();
    let encryptedMD5 = C.AES.encrypt('Test', 'Pass', { salt: data.saltA, hasher: C.algo.MD5}).toString();
    expect(C.AES.decrypt(encryptedMD5, 'Pass', { hasher: C.algo.MD5}).toString(C.enc.Utf8)).toBe('Test');
    expect(encryptedMD5).toBe(encryptedDefault);

    //Different KDFHasher
    expect(encryptedSHA1).not.toBe(encryptedDefault);
    expect(encryptedSHA256).not.toBe(encryptedDefault);
    expect(encryptedSHA512).not.toBe(encryptedDefault);
  });
});
