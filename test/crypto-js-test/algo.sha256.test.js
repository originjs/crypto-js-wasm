import cryptoJs from 'crypto-js/crypto-js';
import cryptoJsWasm from '../../src/index.js';

beforeAll(async () => {
  await cryptoJsWasm.SHA256.loadWasm();
});

const data1 = '';
const data2 = 'Test';
const data3 = 'message digest';
const data4 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

test('testHelper', () => {
  const sha256Wasm = new cryptoJsWasm.algo.SHA256();
  const sha256 = cryptoJs.algo.SHA256.create();
  expect(sha256Wasm.finalize(data1).toString()).toEqual(sha256.finalize(data1).toString());
});

test('algo-sha256-test', () => {
  expect(cryptoJsWasm.SHA256(data1).toString()).toEqual(cryptoJs.SHA256(data1).toString());
  expect(cryptoJsWasm.SHA256(data2).toString()).toEqual(cryptoJs.SHA256(data2).toString());
  expect(cryptoJsWasm.SHA256(data3).toString()).toEqual(cryptoJs.SHA256(data3).toString());
  expect(cryptoJsWasm.SHA256(data4).toString()).toEqual(cryptoJs.SHA256(data4).toString());
});

test('testClone', () => {
  const sha256Wasm = new cryptoJsWasm.algo.SHA256();
  const sha256 = cryptoJs.algo.SHA256.create();
  expect(sha256Wasm.update(data2).clone().finalize().toString()).toEqual(sha256.update(data2).clone().finalize().toString());
});

test('testUpdateAndLongMessage', () => {
  const sha256Wasm = new cryptoJsWasm.algo.SHA256();
  const sha256 = cryptoJs.algo.SHA256.create();
  let i = 0;
  while (i < 100) {
    sha256Wasm.update('12345678901234567890123456789012345678901234567890');
    sha256.update('12345678901234567890123456789012345678901234567890');
    i++;
  }
  expect(sha256Wasm.finalize().toString()).toEqual(sha256.finalize().toString());
});