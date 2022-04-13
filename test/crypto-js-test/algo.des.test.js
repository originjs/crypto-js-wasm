import cryptoJs from 'crypto-js/crypto-js';
import cryptoJsWasm from '../../src/index.js';

beforeAll(async () => {
  await cryptoJsWasm.DES.loadWasm();
});

const key64 = cryptoJs.enc.Hex.parse('0001020304050607');
const key128 = cryptoJs.enc.Hex.parse('000102030405060708090a0b0c0d0e0f');
const key256 = cryptoJs.enc.Hex.parse('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
const iv = cryptoJs.enc.Hex.parse('08090a0b0c0d0e0f');
const data1 = cryptoJs.enc.Hex.parse('001122334455');
const data2 = cryptoJs.enc.Hex.parse('66778899aa');
const data3 = cryptoJs.enc.Hex.parse('bbccddeeff');
const data = cryptoJs.enc.Hex.parse('00112233445566778899aabbccddeeff');

test('testHelper', () => {
  expect(cryptoJsWasm.algo.DES.createEncryptor(key64, {iv: iv}).finalize('Test').toString())
    .toEqual(cryptoJs.algo.DES.createEncryptor(key64, {iv: iv}).finalize('Test').toString());
  expect(cryptoJsWasm.lib.SerializableCipher.encrypt(cryptoJsWasm.algo.DES, 'Test', key64, {iv: iv}).toString())
    .toEqual(cryptoJs.lib.SerializableCipher.encrypt(cryptoJs.algo.DES, 'Test', key64, {iv: iv}).toString());
});

test('testEncryptModeCBC', () => {
  expect(cryptoJsWasm.DES.encrypt('Test', key64, {iv: iv, mode: cryptoJsWasm.mode.CBC}).toString())
    .toEqual(cryptoJs.DES.encrypt('Test', key64, {iv: iv, mode: cryptoJs.mode.CBC}).toString());
});

test('testEncryptModeECB', () => {
  expect(cryptoJsWasm.DES.encrypt('Test', key64, {iv: iv, mode: cryptoJsWasm.mode.ECB}).toString())
    .toEqual(cryptoJs.DES.encrypt('Test', key64, {iv: iv, mode: cryptoJs.mode.ECB}).toString());
});

test('testEncryptModeCFB', () => {
  expect(cryptoJsWasm.DES.encrypt('Test', key64, {iv: iv, mode: cryptoJsWasm.mode.CFB}).toString())
    .toEqual(cryptoJs.DES.encrypt('Test', key64, {iv: iv, mode: cryptoJs.mode.CFB}).toString());
});

test('testEncryptModeOFB', () => {
  expect(cryptoJsWasm.DES.encrypt('Test', key64, {iv: iv, mode: cryptoJsWasm.mode.OFB}).toString())
    .toEqual(cryptoJs.DES.encrypt('Test', key64, {iv: iv, mode: cryptoJs.mode.OFB}).toString());
});

test('testEncryptModeCTR', () => {
  expect(cryptoJsWasm.DES.encrypt('Test', key64, {iv: iv, mode: cryptoJsWasm.mode.CTR}).toString())
    .toEqual(cryptoJs.DES.encrypt('Test', key64, {iv: iv, mode: cryptoJs.mode.CTR}).toString());
});

test('testDecryptModeCBC', () => {
  const encrypted = cryptoJs.DES.encrypt('Test', 'key', {mode: cryptoJs.mode.CBC}).toString();
  expect(cryptoJs.DES.decrypt(encrypted, 'key', {mode: cryptoJs.mode.CBC}).toString(cryptoJs.enc.Utf8)).toEqual('Test');
  expect(cryptoJsWasm.DES.decrypt(encrypted, 'key', {mode: cryptoJsWasm.mode.CBC}).toString(cryptoJsWasm.enc.Utf8)).toEqual('Test');
});

test('testDecryptModeECB', () => {
  const encrypted = cryptoJs.DES.encrypt('Test', 'key', {mode: cryptoJs.mode.ECB}).toString();
  expect(cryptoJs.DES.decrypt(encrypted, 'key', {mode: cryptoJs.mode.ECB}).toString(cryptoJs.enc.Utf8)).toEqual('Test');
  expect(cryptoJsWasm.DES.decrypt(encrypted, 'key', {mode: cryptoJsWasm.mode.ECB}).toString(cryptoJsWasm.enc.Utf8)).toEqual('Test');
});

test('testDecryptModeCFB', () => {
  const encrypted = cryptoJs.DES.encrypt('Test', 'key', {mode: cryptoJs.mode.CFB}).toString();
  expect(cryptoJs.DES.decrypt(encrypted, 'key', {mode: cryptoJs.mode.CFB}).toString(cryptoJs.enc.Utf8)).toEqual('Test');
  expect(cryptoJsWasm.DES.decrypt(encrypted, 'key', {mode: cryptoJsWasm.mode.CFB}).toString(cryptoJsWasm.enc.Utf8)).toEqual('Test');
});

test('testDecryptModeOFB', () => {
  const encrypted = cryptoJs.DES.encrypt('Test', 'key', {mode: cryptoJs.mode.OFB}).toString();
  expect(cryptoJs.DES.decrypt(encrypted, 'key', {mode: cryptoJs.mode.OFB}).toString(cryptoJs.enc.Utf8)).toEqual('Test');
  expect(cryptoJsWasm.DES.decrypt(encrypted, 'key', {mode: cryptoJsWasm.mode.OFB}).toString(cryptoJsWasm.enc.Utf8)).toEqual('Test');
});

test('testDecryptModeCTR', () => {
  const encrypted = cryptoJs.DES.encrypt('Test', 'key', {mode: cryptoJs.mode.CTR}).toString();
  expect(cryptoJs.DES.decrypt(encrypted, 'key', {mode: cryptoJs.mode.CTR}).toString(cryptoJs.enc.Utf8)).toEqual('Test');
  expect(cryptoJsWasm.DES.decrypt(encrypted, 'key', {mode: cryptoJsWasm.mode.CTR}).toString(cryptoJsWasm.enc.Utf8)).toEqual('Test');
});

test('testEncryptKeySize64', () => {
  expect(cryptoJsWasm.DES.encrypt('Test', key64, {iv: iv}).toString())
    .toEqual(cryptoJs.DES.encrypt('Test', key64, {iv: iv}).toString());
});

test('testEncryptKeySize128', () => {
  expect(cryptoJsWasm.DES.encrypt('Test', key128, {iv: iv}).toString())
    .toEqual(cryptoJs.DES.encrypt('Test', key128, {iv: iv}).toString());
  expect(cryptoJsWasm.DES.encrypt('Test', key128, {iv: iv}).toString())
    .toEqual(cryptoJs.DES.encrypt('Test', key64, {iv: iv}).toString());
});

test('testEncryptKeySize256', () => {
  expect(cryptoJsWasm.DES.encrypt('Test', key256, {iv: iv}).toString())
    .toEqual(cryptoJs.DES.encrypt('Test', key256, {iv: iv}).toString());
  expect(cryptoJsWasm.DES.encrypt('Test', key256, {iv: iv}).toString())
    .toEqual(cryptoJs.DES.encrypt('Test', key64, {iv: iv}).toString());
});

test('testDecryptKeySize64', () => {
  const encrypted = cryptoJs.DES.encrypt('Test', key64, {iv: iv}).toString();
  expect(cryptoJs.DES.decrypt(encrypted, key64, {iv: iv}).toString(cryptoJs.enc.Utf8)).toEqual('Test');
  expect(cryptoJsWasm.DES.decrypt(encrypted, key64, {iv: iv}).toString(cryptoJsWasm.enc.Utf8)).toEqual('Test');
});

test('testDecryptKeySize128', () => {
  const encrypted = cryptoJs.DES.encrypt('Test', key128, {iv: iv}).toString();
  expect(cryptoJs.DES.decrypt(encrypted, key128, {iv: iv}).toString(cryptoJs.enc.Utf8)).toEqual('Test');
  expect(cryptoJsWasm.DES.decrypt(encrypted, key128, {iv: iv}).toString(cryptoJsWasm.enc.Utf8)).toEqual('Test');
  expect(cryptoJs.DES.decrypt(encrypted, key64, {iv: iv}).toString(cryptoJs.enc.Utf8)).toEqual('Test');
  expect(cryptoJsWasm.DES.decrypt(encrypted, key64, {iv: iv}).toString(cryptoJsWasm.enc.Utf8)).toEqual('Test');
});

test('testDecryptKeySize256', () => {
  const encrypted = cryptoJs.DES.encrypt('Test', key256, {iv: iv}).toString();
  expect(cryptoJs.DES.decrypt(encrypted, key256, {iv: iv}).toString(cryptoJs.enc.Utf8)).toEqual('Test');
  expect(cryptoJsWasm.DES.decrypt(encrypted, key256, {iv: iv}).toString(cryptoJsWasm.enc.Utf8)).toEqual('Test');
  expect(cryptoJs.DES.decrypt(encrypted, key64, {iv: iv}).toString(cryptoJs.enc.Utf8)).toEqual('Test');
  expect(cryptoJsWasm.DES.decrypt(encrypted, key64, {iv: iv}).toString(cryptoJsWasm.enc.Utf8)).toEqual('Test');
});

test('testMultiPart', () => {
  let DES = cryptoJs.algo.DES.createEncryptor(key64, {iv: iv});
  let DESWasm = cryptoJsWasm.algo.DES.createEncryptor(key64, {iv: iv});
  let ciphertext1 = DES.process(data1);
  let ciphertext2 = DES.process(data2);
  let ciphertext3 = DES.process(data3);
  let ciphertext4 = DES.finalize();
  let ciphertextWasm1 = DESWasm.process(data1);
  let ciphertextWasm2 = DESWasm.process(data2);
  let ciphertextWasm3 = DESWasm.process(data3);
  let ciphertextWasm4 = DESWasm.finalize();
  let ciphertext = ciphertext1.concat(ciphertext2).concat(ciphertext3).concat(ciphertext4);
  let ciphertextWasm = ciphertextWasm1.concat(ciphertextWasm2).concat(ciphertextWasm3).concat(ciphertextWasm4);
  expect(ciphertext1.toString()).toEqual(ciphertextWasm1.toString());
  expect(ciphertext2.toString()).toEqual(ciphertextWasm2.toString());
  expect(ciphertext3.toString()).toEqual(ciphertextWasm3.toString());
  expect(ciphertext4.toString()).toEqual(ciphertextWasm4.toString());
  expect(ciphertext.toString()).toEqual(ciphertextWasm.toString());
  expect(ciphertext.toString(cryptoJs.enc.Base64)).toEqual(cryptoJs.DES.encrypt(data,
    key64, {iv: iv}).toString());
  expect(ciphertextWasm.toString(cryptoJsWasm.enc.Base64)).toEqual(cryptoJsWasm.DES.encrypt(data,
    key64, {iv: iv}).toString());
});

test('testMultiPartECB', () => {
  let DES = cryptoJs.algo.DES.createEncryptor(key64, {iv: iv, mode: cryptoJs.mode.ECB});
  let DESWasm = cryptoJsWasm.algo.DES.createEncryptor(key64, {iv: iv, mode: cryptoJsWasm.mode.ECB});
  let ciphertext1 = DES.process(data1);
  let ciphertext2 = DES.process(data2);
  let ciphertext3 = DES.process(data3);
  let ciphertext4 = DES.finalize();
  let ciphertextWasm1 = DESWasm.process(data1);
  let ciphertextWasm2 = DESWasm.process(data2);
  let ciphertextWasm3 = DESWasm.process(data3);
  let ciphertextWasm4 = DESWasm.finalize();
  let ciphertext = ciphertext1.concat(ciphertext2).concat(ciphertext3).concat(ciphertext4);
  let ciphertextWasm = ciphertextWasm1.concat(ciphertextWasm2).concat(ciphertextWasm3).concat(ciphertextWasm4);
  expect(ciphertext1.toString()).toEqual(ciphertextWasm1.toString());
  expect(ciphertext2.toString()).toEqual(ciphertextWasm2.toString());
  expect(ciphertext3.toString()).toEqual(ciphertextWasm3.toString());
  expect(ciphertext4.toString()).toEqual(ciphertextWasm4.toString());
  expect(ciphertext.toString()).toEqual(ciphertextWasm.toString());
  expect(ciphertext.toString(cryptoJs.enc.Base64)).toEqual(cryptoJs.DES.encrypt(data,
    key64, {mode: cryptoJs.mode.ECB}).toString());
  expect(ciphertextWasm.toString(cryptoJsWasm.enc.Base64)).toEqual(cryptoJsWasm.DES.encrypt(data,
    key64, {mode: cryptoJsWasm.mode.ECB}).toString());
});

test('testMultiPartCFB', () => {
  let DES = cryptoJs.algo.DES.createEncryptor(key64, {iv: iv, mode: cryptoJs.mode.CFB});
  let DESWasm = cryptoJsWasm.algo.DES.createEncryptor(key64, {iv: iv, mode: cryptoJsWasm.mode.CFB});
  let ciphertext1 = DES.process(data1);
  let ciphertext2 = DES.process(data2);
  let ciphertext3 = DES.process(data3);
  let ciphertext4 = DES.finalize();
  let ciphertextWasm1 = DESWasm.process(data1);
  let ciphertextWasm2 = DESWasm.process(data2);
  let ciphertextWasm3 = DESWasm.process(data3);
  let ciphertextWasm4 = DESWasm.finalize();
  let ciphertext = ciphertext1.concat(ciphertext2).concat(ciphertext3).concat(ciphertext4);
  let ciphertextWasm = ciphertextWasm1.concat(ciphertextWasm2).concat(ciphertextWasm3).concat(ciphertextWasm4);
  expect(ciphertext1.toString()).toEqual(ciphertextWasm1.toString());
  expect(ciphertext2.toString()).toEqual(ciphertextWasm2.toString());
  expect(ciphertext3.toString()).toEqual(ciphertextWasm3.toString());
  expect(ciphertext4.toString()).toEqual(ciphertextWasm4.toString());
  expect(ciphertext.toString()).toEqual(ciphertextWasm.toString());
  expect(ciphertext.toString(cryptoJs.enc.Base64)).toEqual(cryptoJs.DES.encrypt(data,
    key64, {iv: iv, mode: cryptoJs.mode.CFB}).toString());
  expect(ciphertextWasm.toString(cryptoJsWasm.enc.Base64)).toEqual(cryptoJsWasm.DES.encrypt(data,
    key64, {iv: iv, mode: cryptoJsWasm.mode.CFB}).toString());
});

test('testMultiPartOFB', () => {
  let DES = cryptoJs.algo.DES.createEncryptor(key64, {iv: iv, mode: cryptoJs.mode.OFB});
  let DESWasm = cryptoJsWasm.algo.DES.createEncryptor(key64, {iv: iv, mode: cryptoJsWasm.mode.OFB});
  let ciphertext1 = DES.process(data1);
  let ciphertext2 = DES.process(data2);
  let ciphertext3 = DES.process(data3);
  let ciphertext4 = DES.finalize();
  let ciphertextWasm1 = DESWasm.process(data1);
  let ciphertextWasm2 = DESWasm.process(data2);
  let ciphertextWasm3 = DESWasm.process(data3);
  let ciphertextWasm4 = DESWasm.finalize();
  let ciphertext = ciphertext1.concat(ciphertext2).concat(ciphertext3).concat(ciphertext4);
  let ciphertextWasm = ciphertextWasm1.concat(ciphertextWasm2).concat(ciphertextWasm3).concat(ciphertextWasm4);
  expect(ciphertext1.toString()).toEqual(ciphertextWasm1.toString());
  expect(ciphertext2.toString()).toEqual(ciphertextWasm2.toString());
  expect(ciphertext3.toString()).toEqual(ciphertextWasm3.toString());
  expect(ciphertext4.toString()).toEqual(ciphertextWasm4.toString());
  expect(ciphertext.toString()).toEqual(ciphertextWasm.toString());
  expect(ciphertext.toString(cryptoJs.enc.Base64)).toEqual(cryptoJs.DES.encrypt(data,
    key64, {iv: iv, mode: cryptoJs.mode.OFB}).toString());
  expect(ciphertextWasm.toString(cryptoJsWasm.enc.Base64)).toEqual(cryptoJsWasm.DES.encrypt(data,
    key64, {iv: iv, mode: cryptoJsWasm.mode.OFB}).toString());
});

test('testMultiPartCTR', () => {
  let DES = cryptoJs.algo.DES.createEncryptor(key64, {iv: iv, mode: cryptoJs.mode.CTR});
  let DESWasm = cryptoJsWasm.algo.DES.createEncryptor(key64, {iv: iv, mode: cryptoJsWasm.mode.CTR});
  let ciphertext1 = DES.process(data1);
  let ciphertext2 = DES.process(data2);
  let ciphertext3 = DES.process(data3);
  let ciphertext4 = DES.finalize();
  let ciphertextWasm1 = DESWasm.process(data1);
  let ciphertextWasm2 = DESWasm.process(data2);
  let ciphertextWasm3 = DESWasm.process(data3);
  let ciphertextWasm4 = DESWasm.finalize();
  let ciphertext = ciphertext1.concat(ciphertext2).concat(ciphertext3).concat(ciphertext4);
  let ciphertextWasm = ciphertextWasm1.concat(ciphertextWasm2).concat(ciphertextWasm3).concat(ciphertextWasm4);
  expect(ciphertext1.toString()).toEqual(ciphertextWasm1.toString());
  expect(ciphertext2.toString()).toEqual(ciphertextWasm2.toString());
  expect(ciphertext3.toString()).toEqual(ciphertextWasm3.toString());
  expect(ciphertext4.toString()).toEqual(ciphertextWasm4.toString());
  expect(ciphertext.toString()).toEqual(ciphertextWasm.toString());
  expect(ciphertext.toString(cryptoJs.enc.Base64)).toEqual(cryptoJs.DES.encrypt(data,
    key64, {iv: iv, mode: cryptoJs.mode.CTR}).toString());
  expect(ciphertextWasm.toString(cryptoJsWasm.enc.Base64)).toEqual(cryptoJsWasm.DES.encrypt(data,
    key64, {iv: iv, mode: cryptoJsWasm.mode.CTR}).toString());
});