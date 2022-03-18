import C from '../src/index';

const data = {};

beforeAll(async () => {
  data.key = C.enc.Hex.parse('000102030405060708090a0b0c0d0e0f');
  // TODO: this should be put in C.Rabbit.loadWasm later
  await C.MD5.loadWasm();
});

describe('algo-rabbit-profile', () => {
  test('profileSinglePartMessage', () => {
    let singlePartMessage = '';
    for (let i = 0; i < 500; i++) {
      singlePartMessage += '12345678901234567890123456789012345678901234567890';
    }

    C.algo.Rabbit.createEncryptor(data.key).finalize(singlePartMessage) + '';
  });

  test('profileMultiPartMessage', () => {
    let rabbit = C.algo.Rabbit.createEncryptor(data.key);
    for (let i = 0; i < 500; i++) {
      rabbit.process('12345678901234567890123456789012345678901234567890') + '';
    }
    rabbit.finalize() + '';
  });
});
