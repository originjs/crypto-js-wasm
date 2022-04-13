import cryptoJs from 'crypto-js/crypto-js';
import cryptoJsWasm from '../../src/index.js';

beforeAll(async () => {
  await cryptoJsWasm.SHA224.loadWasm();
});

const data1 = '';
const data2 = 'Test';
const data3 = 'message digest';
const data4 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

test('testHelper', () => {
  const sha224Wasm = new cryptoJsWasm.algo.SHA224();
  const sha224 = cryptoJs.algo.SHA224.create();
  expect(sha224Wasm.finalize(data1).toString()).toEqual(sha224.finalize(data1).toString());
});

test('algo-sha224-test', () => {
  expect(cryptoJsWasm.SHA224(data1).toString()).toEqual(cryptoJs.SHA224(data1).toString());
  expect(cryptoJsWasm.SHA224(data2).toString()).toEqual(cryptoJs.SHA224(data2).toString());
  expect(cryptoJsWasm.SHA224(data3).toString()).toEqual(cryptoJs.SHA224(data3).toString());
  expect(cryptoJsWasm.SHA224(data4).toString()).toEqual(cryptoJs.SHA224(data4).toString());
});

test('testClone', () => {
  const sha224Wasm = new cryptoJsWasm.algo.SHA224();
  const sha224 = cryptoJs.algo.SHA224.create();
  expect(sha224Wasm.update(data2).clone().finalize().toString()).toEqual(sha224.update(data2).clone().finalize().toString());
});

test('testUpdateAndLongMessage', () => {
  const sha224Wasm = new cryptoJsWasm.algo.SHA224();
  const sha224 = cryptoJs.algo.SHA224.create();
  let i = 0;
  while (i < 100) {
    sha224Wasm.update('12345678901234567890123456789012345678901234567890');
    sha224.update('12345678901234567890123456789012345678901234567890');
    i++;
  }
  expect(sha224Wasm.finalize().toString()).toEqual(sha224.finalize().toString());
});