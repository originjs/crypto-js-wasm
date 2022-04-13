import cryptoJs from 'crypto-js/crypto-js';
import cryptoJsWasm from '../../src/index.js';

beforeAll(async () => {
  await cryptoJsWasm.SHA1.loadWasm();
});

const data1 = '';
const data2 = 'Test';
const data3 = 'message digest';
const data4 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

test('testHelper', () => {
  const sha1Wasm = new cryptoJsWasm.algo.SHA1();
  const sha1 = cryptoJs.algo.SHA1.create();
  expect(sha1Wasm.finalize(data1).toString()).toEqual(sha1.finalize(data1).toString());
});

test('algo-sha1-test', () => {
  expect(cryptoJsWasm.SHA1(data1).toString()).toEqual(cryptoJs.SHA1(data1).toString());
  expect(cryptoJsWasm.SHA1(data2).toString()).toEqual(cryptoJs.SHA1(data2).toString());
  expect(cryptoJsWasm.SHA1(data3).toString()).toEqual(cryptoJs.SHA1(data3).toString());
  expect(cryptoJsWasm.SHA1(data4).toString()).toEqual(cryptoJs.SHA1(data4).toString());
});

test('testClone', () => {
  const sha1Wasm = new cryptoJsWasm.algo.SHA1();
  const sha1 = cryptoJs.algo.SHA1.create();
  expect(sha1Wasm.update(data2).clone().finalize().toString()).toEqual(sha1.update(data2).clone().finalize().toString());
});

test('testUpdateAndLongMessage', () => {
  const sha1Wasm = new cryptoJsWasm.algo.SHA1();
  const sha1 = cryptoJs.algo.SHA1.create();
  let i = 0;
  while (i < 100) {
    sha1Wasm.update('12345678901234567890123456789012345678901234567890');
    sha1.update('12345678901234567890123456789012345678901234567890');
    i++;
  }
  expect(sha1Wasm.finalize().toString()).toEqual(sha1.finalize().toString());
});