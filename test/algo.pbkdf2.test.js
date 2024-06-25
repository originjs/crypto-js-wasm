import C from '../src/index';

beforeAll(async () => {
  await C.SHA256.loadWasm();
});

describe('algo-pbkdf2-test', () => {
  test('testKeySize128', () => {
    expect(C.PBKDF2('password', 'ATHENA.MIT.EDUraeburn', {
      keySize: 128 / 32
    }).toString()).toBe('62929ab995a1111c75c37bc562261ea3');
  });

  test('testKeySize256', () => {
    expect(C.PBKDF2('password', 'ATHENA.MIT.EDUraeburn', {
      keySize: 256 / 32
    }).toString()).toBe('62929ab995a1111c75c37bc562261ea3fb3cdc7e725c4ca87c03cec5bb7663e1');
  });

  test('testKeySize128Iterations2', () => {
    expect(C.PBKDF2('password', 'ATHENA.MIT.EDUraeburn', {
      keySize: 128 / 32,
      iterations: 2
    }).toString()).toBe('262fb72ea65b44ab5ceba7f8c8bfa781');
  });

  test('testKeySize256Iterations2', () => {
    expect(C.PBKDF2('password', 'ATHENA.MIT.EDUraeburn', {
      keySize: 256 / 32,
      iterations: 2
    }).toString()).toBe('262fb72ea65b44ab5ceba7f8c8bfa7815ff9939204eb7357a59a75877d745777');
  });

  test('testKeySize128Iterations1200', () => {
    expect(C.PBKDF2('password', 'ATHENA.MIT.EDUraeburn', {
      keySize: 128 / 32,
      iterations: 1200
    }).toString()).toBe('c76a982415f1acc71dc197273c5b6ada');
  });

  test('testKeySize256Iterations1200', () => {
    expect(C.PBKDF2('password', 'ATHENA.MIT.EDUraeburn', {
      keySize: 256 / 32,
      iterations: 1200
    }).toString()).toBe('c76a982415f1acc71dc197273c5b6ada32f62915ed461718aad32843762433fa');
  });

  test('testKeySize128Iterations5', () => {
    expect(C.PBKDF2('password', C.enc.Hex.parse('1234567878563412'), {
      keySize: 128 / 32,
      iterations: 5
    }).toString()).toBe('74e98b2e9eeddaab3113c1efc6d82b07');
  });

  test('testKeySize256Iterations5', () => {
    expect(C.PBKDF2('password', C.enc.Hex.parse('1234567878563412'), {
      keySize: 256 / 32,
      iterations: 5
    }).toString()).toBe('74e98b2e9eeddaab3113c1efc6d82b073c4860195b3e0737fa21a4778f376321');
  });

  test('testKeySize128Iterations1200PassPhraseEqualsBlockSize', () => {
    expect(C.PBKDF2('XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX', 'pass phrase equals block size', {
      keySize: 128 / 32,
      iterations: 1200
    }).toString()).toBe('c1dfb29a4d2f2fb67c6f78d074d66367');
  });

  test('testKeySize256Iterations1200PassPhraseEqualsBlockSize', () => {
    expect(C.PBKDF2('XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX', 'pass phrase equals block size', {
      keySize: 256 / 32,
      iterations: 1200
    }).toString()).toBe('c1dfb29a4d2f2fb67c6f78d074d663671e6fd4da1e598572b1fecf256cb7cf61');
  });

  test('testKeySize128Iterations1200PassPhraseExceedsBlockSize', () => {
    expect(C.PBKDF2('XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX', 'pass phrase exceeds block size', {
      keySize: 128 / 32,
      iterations: 1200
    }).toString()).toBe('22344bc4b6e32675a8090f3ea80be01d');
  });

  test('testKeySize256Iterations1200PassPhraseExceedsBlockSize', () => {
    expect(C.PBKDF2('XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX', 'pass phrase exceeds block size', {
      keySize: 256 / 32,
      iterations: 1200
    }).toString()).toBe('22344bc4b6e32675a8090f3ea80be01d5f95126a2cddc3facc4a5e6dca04ec58');
  });

  test('testKeySize128Iterations50', () => {
    expect(C.PBKDF2(C.enc.Hex.parse('f09d849e'), 'EXAMPLE.COMpianist', {
      keySize: 128 / 32,
      iterations: 50
    }).toString()).toBe('44b0781253db3141ac4174af29325818');
  });

  test('testKeySize256Iterations50', () => {
    expect(C.PBKDF2(C.enc.Hex.parse('f09d849e'), 'EXAMPLE.COMpianist', {
      keySize: 256 / 32,
      iterations: 50
    }).toString()).toBe('44b0781253db3141ac4174af29325818584698d507a79f9879033dec308a2b77');
  });

  test('testInputIntegrity', () => {
    let password = new C.lib.WordArray([0x12345678]);
    let salt = new C.lib.WordArray([0x12345678]);

    let expectedPassword = password.toString();
    let expectedSalt = salt.toString();

    C.PBKDF2(password, salt);
    expect(password.toString()).toBe(expectedPassword);
    expect(salt.toString()).toBe(expectedSalt);
  });

  test('testHelper', () => {
    expect(C.PBKDF2('password', 'ATHENA.MIT.EDUraeburn', {
      keySize: 128 / 32
    }).toString()).toBe(new C.algo.PBKDF2({
      keySize: 128 / 32
    }).compute('password', 'ATHENA.MIT.EDUraeburn').toString());
  });
});
