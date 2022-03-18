import C from '../src/index';

beforeAll(async () => {
  // the default hasher for EvpKDF is md5
  await C.algo.EvpKDF.loadWasm();
});

describe('algo-evpkdf-profile', () => {
  test('profileKeySize256Iterations20', () => {
    new C.algo.EvpKDF({ keySize: 256/32, iterations: 20 }).compute('password', 'ATHENA.MIT.EDUraeburn');
  });
});
