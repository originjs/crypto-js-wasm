import C from '../src/index';

describe('algo-rsa-test', () => {
  test('testRSAKeyPair', async () => {
    // await C.RSA.loadWasm();
    const RSA = await C.RSAPromise;
    expect(RSA.getKeyContent('private', 'pem')).not.toBe('');
  });

  test('generateRSAKeyPair', async () => {
    const RSA = await C.algo.RSA.fromKeySize(1024);
    expect(RSA.getKeyContent('private', 'pem')).not.toBe('');
  });

  test('generateMultipleRSAKeyPairs', async () => {
    await C.algo.RSA.fromKeySize(1024);
    await C.algo.RSA.fromKeySize(1024);
    const RSA = await C.algo.RSA.fromKeySize(2048);
    expect(RSA.getKeyContent('private', 'pem')).not.toBe('');
  });
});
