import C from '../src/index';

let data = {};
beforeAll(async () => {
  await C.SHA256.loadWasm();
  data.saltA = C.enc.Hex.parse('AA00000000000000');
});

describe('algo-blowfish-test', () => {
  test('testEncrypt', () => {
    let encryptedA = C.Blowfish.encrypt('Test',
      'pass',
      {
        salt: data.saltA,
        hasher: C.algo.SHA256
      }).toString();
    expect(encryptedA).toBe('U2FsdGVkX1+qAAAAAAAAAKTIU8MPrBdH');
  });

  test('testDecrypt', () => {
    let encryptedA = C.Blowfish.encrypt('Test',
      'pass',
      {
        salt: data.saltA,
        hasher: C.algo.SHA256
      }).toString();

    expect(C.Blowfish.decrypt(encryptedA, 'pass', {hasher: C.algo.SHA256}).toString(C.enc.Utf8)).toBe('Test');
  });
});
