import cryptoJs from 'crypto-js/crypto-js';
import cryptoJsWasm from '../../src/index.js';

beforeAll(async () => {
  await cryptoJsWasm.SHA512.loadWasm();
});

const data1 = '';
const data2 = 'Test';
const data3 = 'message digest';
const data4 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

test('testHelper', () => {
  const sha512Wasm = new cryptoJsWasm.algo.SHA512();
  const sha512 = cryptoJs.algo.SHA512.create();
  expect(sha512Wasm.finalize(data1).toString()).toEqual(sha512.finalize(data1).toString());
});

test('algo-sha512-test', () => {
  expect(cryptoJsWasm.SHA512(data1).toString()).toEqual(cryptoJs.SHA512(data1).toString());
  expect(cryptoJsWasm.SHA512(data2).toString()).toEqual(cryptoJs.SHA512(data2).toString());
  expect(cryptoJsWasm.SHA512(data3).toString()).toEqual(cryptoJs.SHA512(data3).toString());
  expect(cryptoJsWasm.SHA512(data4).toString()).toEqual(cryptoJs.SHA512(data4).toString());
});

test('testClone', () => {
  const sha512Wasm = new cryptoJsWasm.algo.SHA512();
  const sha512 = cryptoJs.algo.SHA512.create();
  expect(sha512Wasm.update(data2).clone().finalize().toString()).toEqual(sha512.update(data2).clone().finalize().toString());
});

test('testUpdateAndLongMessage', () => {
  const sha512Wasm = new cryptoJsWasm.algo.SHA512();
  const sha512 = cryptoJs.algo.SHA512.create();
  let i = 0;
  while (i < 100) {
    sha512Wasm.update('12345678901234567890123456789012345678901234567890');
    sha512.update('12345678901234567890123456789012345678901234567890');
    i++;
  }
  expect(sha512Wasm.finalize().toString()).toEqual(sha512.finalize().toString());
});