import cryptoJs from 'crypto-js/crypto-js';
import cryptoJsWasm from '../../src/index.js';

beforeAll(async () => {
  await cryptoJsWasm.TripleDES.loadWasm();
});

const key64 = cryptoJs.enc.Hex.parse('0011223344556677');
const key128 = cryptoJs.enc.Hex.parse('000102030405060708090a0b0c0d0e0f');
const key = cryptoJs.enc.Hex.parse('000102030405060708090a0b0c0d0e0f1011121314151617');
const key256 = cryptoJs.enc.Hex.parse('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
const iv = cryptoJs.enc.Hex.parse('08090a0b0c0d0e0f');
const data1 = cryptoJs.enc.Hex.parse('001122334455');
const data2 = cryptoJs.enc.Hex.parse('66778899aa');
const data3 = cryptoJs.enc.Hex.parse('bbccddeeff');
const data = cryptoJs.enc.Hex.parse('00112233445566778899aabbccddeeff');

test('testHelper', () => {
  expect(cryptoJsWasm.algo.TripleDES.createEncryptor(key, {iv: iv}).finalize('Test').toString())
    .toEqual(cryptoJs.algo.TripleDES.createEncryptor(key, {iv: iv}).finalize('Test').toString());
  expect(cryptoJsWasm.lib.SerializableCipher.encrypt(cryptoJsWasm.algo.TripleDES, 'Test', key, {iv: iv}).toString())
    .toEqual(cryptoJs.lib.SerializableCipher.encrypt(cryptoJs.algo.TripleDES, 'Test', key, {iv: iv}).toString());
});

test('testEncryptModeCBC', () => {
  expect(cryptoJsWasm.TripleDES.encrypt('Test', key, {iv: iv, mode: cryptoJsWasm.mode.CBC}).toString())
    .toEqual(cryptoJs.TripleDES.encrypt('Test', key, {iv: iv, mode: cryptoJs.mode.CBC}).toString());
});

test('testEncryptModeECB', () => {
  expect(cryptoJsWasm.TripleDES.encrypt('Test', key, {iv: iv, mode: cryptoJsWasm.mode.ECB}).toString())
    .toEqual(cryptoJs.TripleDES.encrypt('Test', key, {iv: iv, mode: cryptoJs.mode.ECB}).toString());
});

test('testEncryptModeCFB', () => {
  expect(cryptoJsWasm.TripleDES.encrypt('Test', key, {iv: iv, mode: cryptoJsWasm.mode.CFB}).toString())
    .toEqual(cryptoJs.TripleDES.encrypt('Test', key, {iv: iv, mode: cryptoJs.mode.CFB}).toString());
});

test('testEncryptModeOFB', () => {
  expect(cryptoJsWasm.TripleDES.encrypt('Test', key, {iv: iv, mode: cryptoJsWasm.mode.OFB}).toString())
    .toEqual(cryptoJs.TripleDES.encrypt('Test', key, {iv: iv, mode: cryptoJs.mode.OFB}).toString());
});

test('testEncryptModeCTR', () => {
  expect(cryptoJsWasm.TripleDES.encrypt('Test', key, {iv: iv, mode: cryptoJsWasm.mode.CTR}).toString())
    .toEqual(cryptoJs.TripleDES.encrypt('Test', key, {iv: iv, mode: cryptoJs.mode.CTR}).toString());
});

test('testDecryptModeCBC', () => {
  const encrypted = cryptoJs.TripleDES.encrypt('Test', 'key', {mode: cryptoJs.mode.CBC}).toString();
  expect(cryptoJs.TripleDES.decrypt(encrypted, 'key', {mode: cryptoJs.mode.CBC}).toString(cryptoJs.enc.Utf8)).toEqual('Test');
  expect(cryptoJsWasm.TripleDES.decrypt(encrypted, 'key', {mode: cryptoJsWasm.mode.CBC}).toString(cryptoJsWasm.enc.Utf8)).toEqual('Test');
});

test('testDecryptModeECB', () => {
  const encrypted = cryptoJs.TripleDES.encrypt('Test', 'key', {mode: cryptoJs.mode.ECB}).toString();
  expect(cryptoJs.TripleDES.decrypt(encrypted, 'key', {mode: cryptoJs.mode.ECB}).toString(cryptoJs.enc.Utf8)).toEqual('Test');
  expect(cryptoJsWasm.TripleDES.decrypt(encrypted, 'key', {mode: cryptoJsWasm.mode.ECB}).toString(cryptoJsWasm.enc.Utf8)).toEqual('Test');
});

test('testDecryptModeCFB', () => {
  const encrypted = cryptoJs.TripleDES.encrypt('Test', 'key', {mode: cryptoJs.mode.CFB}).toString();
  expect(cryptoJs.TripleDES.decrypt(encrypted, 'key', {mode: cryptoJs.mode.CFB}).toString(cryptoJs.enc.Utf8)).toEqual('Test');
  expect(cryptoJsWasm.TripleDES.decrypt(encrypted, 'key', {mode: cryptoJsWasm.mode.CFB}).toString(cryptoJsWasm.enc.Utf8)).toEqual('Test');
});

test('testDecryptModeOFB', () => {
  const encrypted = cryptoJs.TripleDES.encrypt('Test', 'key', {mode: cryptoJs.mode.OFB}).toString();
  expect(cryptoJs.TripleDES.decrypt(encrypted, 'key', {mode: cryptoJs.mode.OFB}).toString(cryptoJs.enc.Utf8)).toEqual('Test');
  expect(cryptoJsWasm.TripleDES.decrypt(encrypted, 'key', {mode: cryptoJsWasm.mode.OFB}).toString(cryptoJsWasm.enc.Utf8)).toEqual('Test');
});

test('testDecryptModeCTR', () => {
  const encrypted = cryptoJs.TripleDES.encrypt('Test', 'key', {mode: cryptoJs.mode.CTR}).toString();
  expect(cryptoJs.TripleDES.decrypt(encrypted, 'key', {mode: cryptoJs.mode.CTR}).toString(cryptoJs.enc.Utf8)).toEqual('Test');
  expect(cryptoJsWasm.TripleDES.decrypt(encrypted, 'key', {mode: cryptoJsWasm.mode.CTR}).toString(cryptoJsWasm.enc.Utf8)).toEqual('Test');
});

test('testEncryptKeySize64', () => {
  expect(cryptoJsWasm.TripleDES.encrypt('Test', key64, {iv: iv}).toString())
    .toEqual(cryptoJs.TripleDES.encrypt('Test', key64, {iv: iv}).toString());
  const extendedKey = cryptoJs.enc.Hex.parse('001122334455667700112233445566770011223344556677');
  expect(cryptoJsWasm.TripleDES.encrypt('Test', key64, {iv: iv}).toString())
    .toEqual(cryptoJs.TripleDES.encrypt('Test', extendedKey, {iv: iv}).toString());
});

test('testEncryptKeySize128', () => {
  expect(cryptoJsWasm.TripleDES.encrypt('Test', key128, {iv: iv}).toString())
    .toEqual(cryptoJs.TripleDES.encrypt('Test', key128, {iv: iv}).toString());
  const extendedKey = cryptoJs.enc.Hex.parse('000102030405060708090a0b0c0d0e0f0001020304050607');
  expect(cryptoJsWasm.TripleDES.encrypt('Test', key128, {iv: iv}).toString())
    .toEqual(cryptoJs.TripleDES.encrypt('Test', extendedKey, {iv: iv}).toString());
});

test('testEncryptKeySize256', () => {
  expect(cryptoJsWasm.TripleDES.encrypt('Test', key256, {iv: iv}).toString())
    .toEqual(cryptoJs.TripleDES.encrypt('Test', key256, {iv: iv}).toString());
  const truncatedKey = cryptoJs.enc.Hex.parse('000102030405060708090a0b0c0d0e0f1011121314151617');
  expect(cryptoJsWasm.TripleDES.encrypt('Test', key256, {iv: iv}).toString())
    .toEqual(cryptoJs.TripleDES.encrypt('Test', truncatedKey, {iv: iv}).toString());
});

test('testDecryptKeySize64', () => {
  const encrypted = cryptoJs.TripleDES.encrypt('Test', key64, {iv: iv}).toString();
  expect(cryptoJs.TripleDES.decrypt(encrypted, key64, {iv: iv}).toString(cryptoJs.enc.Utf8)).toEqual('Test');
  expect(cryptoJsWasm.TripleDES.decrypt(encrypted, key64, {iv: iv}).toString(cryptoJsWasm.enc.Utf8)).toEqual('Test');
  const extendedKey = cryptoJs.enc.Hex.parse('001122334455667700112233445566770011223344556677');
  expect(cryptoJs.TripleDES.decrypt(encrypted, extendedKey, {iv: iv}).toString(cryptoJs.enc.Utf8)).toEqual('Test');
  expect(cryptoJsWasm.TripleDES.decrypt(encrypted, extendedKey, {iv: iv}).toString(cryptoJsWasm.enc.Utf8)).toEqual('Test');
});

test('testDecryptKeySize128', () => {
  const encrypted = cryptoJs.TripleDES.encrypt('Test', key128, {iv: iv}).toString();
  expect(cryptoJs.TripleDES.decrypt(encrypted, key128, {iv: iv}).toString(cryptoJs.enc.Utf8)).toEqual('Test');
  expect(cryptoJsWasm.TripleDES.decrypt(encrypted, key128, {iv: iv}).toString(cryptoJsWasm.enc.Utf8)).toEqual('Test');
  const extendedKey = cryptoJs.enc.Hex.parse('000102030405060708090a0b0c0d0e0f0001020304050607');
  expect(cryptoJs.TripleDES.decrypt(encrypted, extendedKey, {iv: iv}).toString(cryptoJs.enc.Utf8)).toEqual('Test');
  expect(cryptoJsWasm.TripleDES.decrypt(encrypted, extendedKey, {iv: iv}).toString(cryptoJsWasm.enc.Utf8)).toEqual('Test');
});

test('testDecryptKeySize256', () => {
  const encrypted = cryptoJs.TripleDES.encrypt('Test', key256, {iv: iv}).toString();
  expect(cryptoJs.TripleDES.decrypt(encrypted, key256, {iv: iv}).toString(cryptoJs.enc.Utf8)).toEqual('Test');
  expect(cryptoJsWasm.TripleDES.decrypt(encrypted, key256, {iv: iv}).toString(cryptoJsWasm.enc.Utf8)).toEqual('Test');
  const truncatedKey = cryptoJs.enc.Hex.parse('000102030405060708090a0b0c0d0e0f1011121314151617');
  expect(cryptoJs.TripleDES.decrypt(encrypted, truncatedKey, {iv: iv}).toString(cryptoJs.enc.Utf8)).toEqual('Test');
  expect(cryptoJsWasm.TripleDES.decrypt(encrypted, truncatedKey, {iv: iv}).toString(cryptoJsWasm.enc.Utf8)).toEqual('Test');
});

test('testMultiPart', () => {
  let TripleDES = cryptoJs.algo.TripleDES.createEncryptor(key, {iv: iv});
  let TripleDESWasm = cryptoJsWasm.algo.TripleDES.createEncryptor(key, {iv: iv});
  let ciphertext1 = TripleDES.process(data1);
  let ciphertext2 = TripleDES.process(data2);
  let ciphertext3 = TripleDES.process(data3);
  let ciphertext4 = TripleDES.finalize();
  let ciphertextWasm1 = TripleDESWasm.process(data1);
  let ciphertextWasm2 = TripleDESWasm.process(data2);
  let ciphertextWasm3 = TripleDESWasm.process(data3);
  let ciphertextWasm4 = TripleDESWasm.finalize();
  let ciphertext = ciphertext1.concat(ciphertext2).concat(ciphertext3).concat(ciphertext4);
  let ciphertextWasm = ciphertextWasm1.concat(ciphertextWasm2).concat(ciphertextWasm3).concat(ciphertextWasm4);
  expect(ciphertext1.toString()).toEqual(ciphertextWasm1.toString());
  expect(ciphertext2.toString()).toEqual(ciphertextWasm2.toString());
  expect(ciphertext3.toString()).toEqual(ciphertextWasm3.toString());
  expect(ciphertext4.toString()).toEqual(ciphertextWasm4.toString());
  expect(ciphertext.toString()).toEqual(ciphertextWasm.toString());
  expect(ciphertext.toString(cryptoJs.enc.Base64)).toEqual(cryptoJs.TripleDES.encrypt(data,
    key, {iv: iv}).toString());
  expect(ciphertextWasm.toString(cryptoJsWasm.enc.Base64)).toEqual(cryptoJsWasm.TripleDES.encrypt(data,
    key, {iv: iv}).toString());
});

test('testMultiPartECB', () => {
  let TripleDES = cryptoJs.algo.TripleDES.createEncryptor(key, {iv: iv, mode: cryptoJs.mode.ECB});
  let TripleDESWasm = cryptoJsWasm.algo.TripleDES.createEncryptor(key, {iv: iv, mode: cryptoJsWasm.mode.ECB});
  let ciphertext1 = TripleDES.process(data1);
  let ciphertext2 = TripleDES.process(data2);
  let ciphertext3 = TripleDES.process(data3);
  let ciphertext4 = TripleDES.finalize();
  let ciphertextWasm1 = TripleDESWasm.process(data1);
  let ciphertextWasm2 = TripleDESWasm.process(data2);
  let ciphertextWasm3 = TripleDESWasm.process(data3);
  let ciphertextWasm4 = TripleDESWasm.finalize();
  let ciphertext = ciphertext1.concat(ciphertext2).concat(ciphertext3).concat(ciphertext4);
  let ciphertextWasm = ciphertextWasm1.concat(ciphertextWasm2).concat(ciphertextWasm3).concat(ciphertextWasm4);
  expect(ciphertext1.toString()).toEqual(ciphertextWasm1.toString());
  expect(ciphertext2.toString()).toEqual(ciphertextWasm2.toString());
  expect(ciphertext3.toString()).toEqual(ciphertextWasm3.toString());
  expect(ciphertext4.toString()).toEqual(ciphertextWasm4.toString());
  expect(ciphertext.toString()).toEqual(ciphertextWasm.toString());
  expect(ciphertext.toString(cryptoJs.enc.Base64)).toEqual(cryptoJs.TripleDES.encrypt(data,
    key, {mode: cryptoJs.mode.ECB}).toString());
  expect(ciphertextWasm.toString(cryptoJsWasm.enc.Base64)).toEqual(cryptoJsWasm.TripleDES.encrypt(data,
    key, {mode: cryptoJsWasm.mode.ECB}).toString());
});

test('testMultiPartCFB', () => {
  let TripleDES = cryptoJs.algo.TripleDES.createEncryptor(key, {iv: iv, mode: cryptoJs.mode.CFB});
  let TripleDESWasm = cryptoJsWasm.algo.TripleDES.createEncryptor(key, {iv: iv, mode: cryptoJsWasm.mode.CFB});
  let ciphertext1 = TripleDES.process(data1);
  let ciphertext2 = TripleDES.process(data2);
  let ciphertext3 = TripleDES.process(data3);
  let ciphertext4 = TripleDES.finalize();
  let ciphertextWasm1 = TripleDESWasm.process(data1);
  let ciphertextWasm2 = TripleDESWasm.process(data2);
  let ciphertextWasm3 = TripleDESWasm.process(data3);
  let ciphertextWasm4 = TripleDESWasm.finalize();
  let ciphertext = ciphertext1.concat(ciphertext2).concat(ciphertext3).concat(ciphertext4);
  let ciphertextWasm = ciphertextWasm1.concat(ciphertextWasm2).concat(ciphertextWasm3).concat(ciphertextWasm4);
  expect(ciphertext1.toString()).toEqual(ciphertextWasm1.toString());
  expect(ciphertext2.toString()).toEqual(ciphertextWasm2.toString());
  expect(ciphertext3.toString()).toEqual(ciphertextWasm3.toString());
  expect(ciphertext4.toString()).toEqual(ciphertextWasm4.toString());
  expect(ciphertext.toString()).toEqual(ciphertextWasm.toString());
  expect(ciphertext.toString(cryptoJs.enc.Base64)).toEqual(cryptoJs.TripleDES.encrypt(data,
    key, {iv: iv, mode: cryptoJs.mode.CFB}).toString());
  expect(ciphertextWasm.toString(cryptoJsWasm.enc.Base64)).toEqual(cryptoJsWasm.TripleDES.encrypt(data,
    key, {iv: iv, mode: cryptoJsWasm.mode.CFB}).toString());
});

test('testMultiPartOFB', () => {
  let TripleDES = cryptoJs.algo.TripleDES.createEncryptor(key, {iv: iv, mode: cryptoJs.mode.OFB});
  let TripleDESWasm = cryptoJsWasm.algo.TripleDES.createEncryptor(key, {iv: iv, mode: cryptoJsWasm.mode.OFB});
  let ciphertext1 = TripleDES.process(data1);
  let ciphertext2 = TripleDES.process(data2);
  let ciphertext3 = TripleDES.process(data3);
  let ciphertext4 = TripleDES.finalize();
  let ciphertextWasm1 = TripleDESWasm.process(data1);
  let ciphertextWasm2 = TripleDESWasm.process(data2);
  let ciphertextWasm3 = TripleDESWasm.process(data3);
  let ciphertextWasm4 = TripleDESWasm.finalize();
  let ciphertext = ciphertext1.concat(ciphertext2).concat(ciphertext3).concat(ciphertext4);
  let ciphertextWasm = ciphertextWasm1.concat(ciphertextWasm2).concat(ciphertextWasm3).concat(ciphertextWasm4);
  expect(ciphertext1.toString()).toEqual(ciphertextWasm1.toString());
  expect(ciphertext2.toString()).toEqual(ciphertextWasm2.toString());
  expect(ciphertext3.toString()).toEqual(ciphertextWasm3.toString());
  expect(ciphertext4.toString()).toEqual(ciphertextWasm4.toString());
  expect(ciphertext.toString()).toEqual(ciphertextWasm.toString());
  expect(ciphertext.toString(cryptoJs.enc.Base64)).toEqual(cryptoJs.TripleDES.encrypt(data,
    key, {iv: iv, mode: cryptoJs.mode.OFB}).toString());
  expect(ciphertextWasm.toString(cryptoJsWasm.enc.Base64)).toEqual(cryptoJsWasm.TripleDES.encrypt(data,
    key, {iv: iv, mode: cryptoJsWasm.mode.OFB}).toString());
});

test('testMultiPartCTR', () => {
  let TripleDES = cryptoJs.algo.TripleDES.createEncryptor(key, {iv: iv, mode: cryptoJs.mode.CTR});
  let TripleDESWasm = cryptoJsWasm.algo.TripleDES.createEncryptor(key, {iv: iv, mode: cryptoJsWasm.mode.CTR});
  let ciphertext1 = TripleDES.process(data1);
  let ciphertext2 = TripleDES.process(data2);
  let ciphertext3 = TripleDES.process(data3);
  let ciphertext4 = TripleDES.finalize();
  let ciphertextWasm1 = TripleDESWasm.process(data1);
  let ciphertextWasm2 = TripleDESWasm.process(data2);
  let ciphertextWasm3 = TripleDESWasm.process(data3);
  let ciphertextWasm4 = TripleDESWasm.finalize();
  let ciphertext = ciphertext1.concat(ciphertext2).concat(ciphertext3).concat(ciphertext4);
  let ciphertextWasm = ciphertextWasm1.concat(ciphertextWasm2).concat(ciphertextWasm3).concat(ciphertextWasm4);
  expect(ciphertext1.toString()).toEqual(ciphertextWasm1.toString());
  expect(ciphertext2.toString()).toEqual(ciphertextWasm2.toString());
  expect(ciphertext3.toString()).toEqual(ciphertextWasm3.toString());
  expect(ciphertext4.toString()).toEqual(ciphertextWasm4.toString());
  expect(ciphertext.toString()).toEqual(ciphertextWasm.toString());
  expect(ciphertext.toString(cryptoJs.enc.Base64)).toEqual(cryptoJs.TripleDES.encrypt(data,
    key, {iv: iv, mode: cryptoJs.mode.CTR}).toString());
  expect(ciphertextWasm.toString(cryptoJsWasm.enc.Base64)).toEqual(cryptoJsWasm.TripleDES.encrypt(data,
    key, {iv: iv, mode: cryptoJsWasm.mode.CTR}).toString());
});