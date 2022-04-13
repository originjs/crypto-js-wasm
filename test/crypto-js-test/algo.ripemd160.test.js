import cryptoJs from 'crypto-js/crypto-js';
import cryptoJsWasm from '../../src/index.js';

beforeAll(async () => {
  await cryptoJsWasm.RIPEMD160.loadWasm();
});

const data1 = '';
const data2 = 'Test';
const data3 = 'message digest';
const data4 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

test('testHelper', () => {
  const ripemd160Wasm = new cryptoJsWasm.algo.RIPEMD160();
  const ripemd160 = cryptoJs.algo.RIPEMD160.create();
  expect(ripemd160Wasm.finalize(data1).toString()).toEqual(ripemd160.finalize(data1).toString());
});

test('algo-ripemd160-test', () => {
  expect(cryptoJsWasm.RIPEMD160(data1).toString()).toEqual(cryptoJs.RIPEMD160(data1).toString());
  expect(cryptoJsWasm.RIPEMD160(data2).toString()).toEqual(cryptoJs.RIPEMD160(data2).toString());
  expect(cryptoJsWasm.RIPEMD160(data3).toString()).toEqual(cryptoJs.RIPEMD160(data3).toString());
  expect(cryptoJsWasm.RIPEMD160(data4).toString()).toEqual(cryptoJs.RIPEMD160(data4).toString());
});

test('testClone', () => {
  const ripemd160Wasm = new cryptoJsWasm.algo.RIPEMD160();
  const ripemd160 = cryptoJs.algo.RIPEMD160.create();
  expect(ripemd160Wasm.update(data2).clone().finalize().toString()).toEqual(ripemd160.update(data2).clone().finalize().toString());
});

test('testUpdateAndLongMessage', () => {
  const ripemd160Wasm = new cryptoJsWasm.algo.RIPEMD160();
  const ripemd160 = cryptoJs.algo.RIPEMD160.create();
  let i = 0;
  while (i < 100) {
    ripemd160Wasm.update('12345678901234567890123456789012345678901234567890');
    ripemd160.update('12345678901234567890123456789012345678901234567890');
    i++;
  }
  expect(ripemd160Wasm.finalize().toString()).toEqual(ripemd160.finalize().toString());
});