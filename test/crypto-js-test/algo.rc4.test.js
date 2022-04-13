import cryptoJs from 'crypto-js/crypto-js';
import cryptoJsWasm from '../../src/index.js';

beforeAll(async () => {
  await cryptoJsWasm.RC4.loadWasm();
});

const key = cryptoJs.enc.Hex.parse('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
const data1 = cryptoJs.enc.Hex.parse('001122334455001122334455001122334455001122334455');
const data2 = cryptoJs.enc.Hex.parse('66778899aa');
const data3 = cryptoJs.enc.Hex.parse('bbccddeeff');
const data = cryptoJs.enc.Hex.parse('00112233445500112233445500112233445500112233445566778899aabbccddeeff');

test('testHelper', () => {
  expect(cryptoJsWasm.algo.RC4.createEncryptor(key).finalize('Test').toString())
    .toEqual(cryptoJs.algo.RC4.createEncryptor(key).finalize('Test').toString());
  expect(cryptoJsWasm.lib.SerializableCipher.encrypt(cryptoJsWasm.algo.RC4, 'Test', key).toString())
    .toEqual(cryptoJs.lib.SerializableCipher.encrypt(cryptoJs.algo.RC4, 'Test', key).toString());
});

test('testEncrypt', () => {
  expect(cryptoJsWasm.RC4.encrypt('Test', key).toString()).toEqual(cryptoJs.RC4.encrypt('Test', key).toString());
});

test('testDecrypt', () => {
  const encrypted = cryptoJs.RC4.encrypt('Test', 'key').toString();
  expect(cryptoJs.RC4.decrypt(encrypted, 'key').toString(cryptoJs.enc.Utf8)).toEqual('Test');
  expect(cryptoJsWasm.RC4.decrypt(encrypted, 'key').toString(cryptoJsWasm.enc.Utf8)).toEqual('Test');
});

test('testMultiPart', () => {
  let rc4 = cryptoJs.algo.RC4.createEncryptor(key);
  let rc4Wasm = cryptoJsWasm.algo.RC4.createEncryptor(key);
  let ciphertext1 = rc4.process(data1);
  let ciphertext2 = rc4.process(data2);
  let ciphertext3 = rc4.process(data3);
  let ciphertext4 = rc4.finalize();
  let ciphertextWasm1 = rc4Wasm.process(data1);
  let ciphertextWasm2 = rc4Wasm.process(data2);
  let ciphertextWasm3 = rc4Wasm.process(data3);
  let ciphertextWasm4 = rc4Wasm.finalize();
  let ciphertext = ciphertext1.concat(ciphertext2).concat(ciphertext3).concat(ciphertext4);
  let ciphertextWasm = ciphertextWasm1.concat(ciphertextWasm2).concat(ciphertextWasm3).concat(ciphertextWasm4);
  expect(ciphertext1.toString()).toEqual(ciphertextWasm1.toString());
  expect(ciphertext2.toString()).toEqual(ciphertextWasm2.toString());
  expect(ciphertext3.toString()).toEqual(ciphertextWasm3.toString());
  expect(ciphertext4.toString()).toEqual(ciphertextWasm4.toString());
  expect(ciphertext.toString()).toEqual(ciphertextWasm.toString());
  expect(ciphertext.toString(cryptoJs.enc.Base64)).toEqual(cryptoJs.RC4.encrypt(data, key).toString());
  expect(ciphertextWasm.toString(cryptoJsWasm.enc.Base64)).toEqual(cryptoJsWasm.RC4.encrypt(data, key).toString());
});