import cryptoJs from 'crypto-js/crypto-js';
import cryptoJsWasm from '../../src/index.js';

beforeAll(async () => {
  await cryptoJsWasm.MD5.loadWasm();
});

const data1 = '';
const data2 = 'Test';
const data3 = 'message digest';
const data4 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

test('testHelper', () => {
  const md5Wasm = new cryptoJsWasm.algo.MD5();
  const md5 = cryptoJs.algo.MD5.create();
  expect(md5Wasm.finalize(data1).toString()).toEqual(md5.finalize(data1).toString());
});

test('algo-md5-test', () => {
  expect(cryptoJsWasm.MD5(data1).toString()).toEqual(cryptoJs.MD5(data1).toString());
  expect(cryptoJsWasm.MD5(data2).toString()).toEqual(cryptoJs.MD5(data2).toString());
  expect(cryptoJsWasm.MD5(data3).toString()).toEqual(cryptoJs.MD5(data3).toString());
  expect(cryptoJsWasm.MD5(data4).toString()).toEqual(cryptoJs.MD5(data4).toString());
});

test('testClone', () => {
  const md5Wasm = new cryptoJsWasm.algo.MD5();
  const md5 = cryptoJs.algo.MD5.create();
  expect(md5Wasm.update(data2).clone().finalize().toString()).toEqual(md5.update(data2).clone().finalize().toString());
});

test('testUpdateAndLongMessage', () => {
  const md5Wasm = new cryptoJsWasm.algo.MD5();
  const md5 = cryptoJs.algo.MD5.create();
  let i = 0;
  while (i < 100) {
    md5Wasm.update('12345678901234567890123456789012345678901234567890');
    md5.update('12345678901234567890123456789012345678901234567890');
    i++;
  }
  expect(md5Wasm.finalize().toString()).toEqual(md5.finalize().toString());
});