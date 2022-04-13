import cryptoJs from 'crypto-js/crypto-js';
import cryptoJsWasm from '../../src/index.js';

beforeAll(async () => {
  await cryptoJsWasm.SHA3.loadWasm();
});

const data1 = '';
const data2 = 'Test';
const data3 = 'message digest';
const data4 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

test('testHelper', () => {
  const sha3Wasm = new cryptoJsWasm.algo.SHA3();
  const sha3 = cryptoJs.algo.SHA3.create();
  expect(sha3Wasm.finalize(data1).toString()).toEqual(sha3.finalize(data1).toString());
});

test('algo-sha3-test', () => {
  expect(cryptoJsWasm.SHA3(data1).toString()).toEqual(cryptoJs.SHA3(data1).toString());
  expect(cryptoJsWasm.SHA3(data2).toString()).toEqual(cryptoJs.SHA3(data2).toString());
  expect(cryptoJsWasm.SHA3(data3).toString()).toEqual(cryptoJs.SHA3(data3).toString());
  expect(cryptoJsWasm.SHA3(data4).toString()).toEqual(cryptoJs.SHA3(data4).toString());
});

test('testOutputLength', () => {
  expect(cryptoJsWasm.SHA3(data1).toString()).toEqual(cryptoJs.SHA3(data1, { outputLength: 512 }).toString());
  expect(cryptoJsWasm.SHA3(data1, { outputLength: 512 }).toString()).toEqual(cryptoJs.SHA3(data1, { outputLength: 512 }).toString());
  expect(cryptoJsWasm.SHA3(data2, { outputLength: 384 }).toString()).toEqual(cryptoJs.SHA3(data2, { outputLength: 384 }).toString());
  expect(cryptoJsWasm.SHA3(data3, { outputLength: 256 }).toString()).toEqual(cryptoJs.SHA3(data3, { outputLength: 256 }).toString());
  expect(cryptoJsWasm.SHA3(data4, { outputLength: 224 }).toString()).toEqual(cryptoJs.SHA3(data4, { outputLength: 224 }).toString());
});

test('testClone', () => {
  const sha3Wasm = new cryptoJsWasm.algo.SHA3();
  const sha3 = cryptoJs.algo.SHA3.create();
  expect(sha3Wasm.update(data2).clone().finalize().toString()).toEqual(sha3.update(data2).clone().finalize().toString());
});

test('testUpdateAndLongMessage', () => {
  const sha3Wasm = new cryptoJsWasm.algo.SHA3();
  const sha3 = cryptoJs.algo.SHA3.create();
  let i = 0;
  while (i < 100) {
    sha3Wasm.update('12345678901234567890123456789012345678901234567890');
    sha3.update('12345678901234567890123456789012345678901234567890');
    i++;
  }
  expect(sha3Wasm.finalize().toString()).toEqual(sha3.finalize().toString());
});