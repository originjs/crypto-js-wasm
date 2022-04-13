import cryptoJs from 'crypto-js/crypto-js';
import cryptoJsWasm from '../../src/index.js';

beforeAll(async () => {
  await cryptoJsWasm.SHA384.loadWasm();
});

const data1 = '';
const data2 = 'Test';
const data3 = 'message digest';
const data4 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

test('testHelper', () => {
  const sha384Wasm = new cryptoJsWasm.algo.SHA384();
  const sha384 = cryptoJs.algo.SHA384.create();
  expect(sha384Wasm.finalize(data1).toString()).toEqual(sha384.finalize(data1).toString());
});

test('algo-sha384-test', () => {
  expect(cryptoJsWasm.SHA384(data1).toString()).toEqual(cryptoJs.SHA384(data1).toString());
  expect(cryptoJsWasm.SHA384(data2).toString()).toEqual(cryptoJs.SHA384(data2).toString());
  expect(cryptoJsWasm.SHA384(data3).toString()).toEqual(cryptoJs.SHA384(data3).toString());
  expect(cryptoJsWasm.SHA384(data4).toString()).toEqual(cryptoJs.SHA384(data4).toString());
});

test('testClone', () => {
  const sha384Wasm = new cryptoJsWasm.algo.SHA384();
  const sha384 = cryptoJs.algo.SHA384.create();
  expect(sha384Wasm.update(data2).clone().finalize().toString()).toEqual(sha384.update(data2).clone().finalize().toString());
});

test('testUpdateAndLongMessage', () => {
  const sha384Wasm = new cryptoJsWasm.algo.SHA384();
  const sha384 = cryptoJs.algo.SHA384.create();
  let i = 0;
  while (i < 100) {
    sha384Wasm.update('12345678901234567890123456789012345678901234567890');
    sha384.update('12345678901234567890123456789012345678901234567890');
    i++;
  }
  expect(sha384Wasm.finalize().toString()).toEqual(sha384.finalize().toString());
});