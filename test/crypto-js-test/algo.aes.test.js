import cryptoJs from 'crypto-js/crypto-js';
import cryptoJsWasm from '../../src/index.js';

beforeAll(async () => {
  await cryptoJsWasm.AES.loadWasm();
  await cryptoJsWasm.SHA256.loadWasm();
});

const key128 = cryptoJs.enc.Hex.parse('000102030405060708090a0b0c0d0e0f');
const key192 = cryptoJs.enc.Hex.parse('000102030405060708090a0b0c0d0e0f1011121314151617');
const key256 = cryptoJs.enc.Hex.parse('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
const iv = cryptoJs.enc.Hex.parse('101112131415161718191a1b1c1d1e1f');
const data1 = cryptoJs.enc.Hex.parse('001122334455001122334455001122334455001122334455');
const data2 = cryptoJs.enc.Hex.parse('66778899aa');
const data3 = cryptoJs.enc.Hex.parse('bbccddeeff');
const data = cryptoJs.enc.Hex.parse('00112233445500112233445500112233445500112233445566778899aabbccddeeff');

test('testHelper', () => {
  expect(cryptoJsWasm.algo.AES.createEncryptor(cryptoJsWasm.SHA256('key'), { iv: iv }).finalize('Test').toString())
    .toEqual(cryptoJs.algo.AES.createEncryptor(cryptoJs.SHA256('key'), { iv: iv }).finalize('Test').toString());
  expect(cryptoJsWasm.lib.SerializableCipher.encrypt(cryptoJsWasm.algo.AES, 'Test', cryptoJsWasm.SHA256('key'), { iv: iv }).toString())
    .toEqual(cryptoJs.lib.SerializableCipher.encrypt(cryptoJs.algo.AES, 'Test', cryptoJs.SHA256('key'), { iv: iv }).toString());
});

test('testEncryptModeCBC', () => {
  expect(cryptoJsWasm.AES.encrypt('Test', key256, { iv: iv, mode: cryptoJsWasm.mode.CBC }).toString())
    .toEqual(cryptoJs.AES.encrypt('Test', key256, { iv: iv, mode: cryptoJs.mode.CBC }).toString());
});

test('testEncryptModeECB', () => {
  expect(cryptoJsWasm.AES.encrypt('Test', key256, { iv: iv, mode: cryptoJsWasm.mode.ECB }).toString())
    .toEqual(cryptoJs.AES.encrypt('Test', key256, { iv: iv, mode: cryptoJs.mode.ECB }).toString());
});

test('testEncryptModeCFB', () => {
  expect(cryptoJsWasm.AES.encrypt('Test', key256, { iv: iv, mode: cryptoJsWasm.mode.CFB }).toString())
    .toEqual(cryptoJs.AES.encrypt('Test', key256, { iv: iv, mode: cryptoJs.mode.CFB }).toString());
});

test('testEncryptModeOFB', () => {
  expect(cryptoJsWasm.AES.encrypt('Test', key256, { iv: iv, mode: cryptoJsWasm.mode.OFB }).toString())
    .toEqual(cryptoJs.AES.encrypt('Test', key256, { iv: iv, mode: cryptoJs.mode.OFB }).toString());
});

test('testEncryptModeCTR', () => {
  expect(cryptoJsWasm.AES.encrypt('Test', key256, { iv: iv, mode: cryptoJsWasm.mode.CTR }).toString())
    .toEqual(cryptoJs.AES.encrypt('Test', key256, { iv: iv, mode: cryptoJs.mode.CTR }).toString());
});

test('testDecryptModeCBC', () => {
  const encrypted = cryptoJs.AES.encrypt('Test', 'key', { mode: cryptoJs.mode.CBC }).toString();
  expect(cryptoJs.AES.decrypt(encrypted, 'key', { mode: cryptoJs.mode.CBC }).toString(cryptoJs.enc.Utf8)).toEqual('Test');
  expect(cryptoJsWasm.AES.decrypt(encrypted, 'key', { mode: cryptoJsWasm.mode.CBC }).toString(cryptoJsWasm.enc.Utf8)).toEqual('Test');
});

test('testDecryptModeECB', () => {
  const encrypted = cryptoJs.AES.encrypt('Test', 'key', { mode: cryptoJs.mode.ECB }).toString();
  expect(cryptoJs.AES.decrypt(encrypted, 'key', { mode: cryptoJs.mode.ECB }).toString(cryptoJs.enc.Utf8)).toEqual('Test');
  expect(cryptoJsWasm.AES.decrypt(encrypted, 'key', { mode: cryptoJsWasm.mode.ECB }).toString(cryptoJsWasm.enc.Utf8)).toEqual('Test');
});

test('testDecryptModeCFB', () => {
  const encrypted = cryptoJs.AES.encrypt('Test', 'key', { mode: cryptoJs.mode.CFB }).toString();
  expect(cryptoJs.AES.decrypt(encrypted, 'key', { mode: cryptoJs.mode.CFB }).toString(cryptoJs.enc.Utf8)).toEqual('Test');
  expect(cryptoJsWasm.AES.decrypt(encrypted, 'key', { mode: cryptoJsWasm.mode.CFB }).toString(cryptoJsWasm.enc.Utf8)).toEqual('Test');
});

test('testDecryptModeOFB', () => {
  const encrypted = cryptoJs.AES.encrypt('Test', 'key', { mode: cryptoJs.mode.OFB }).toString();
  expect(cryptoJs.AES.decrypt(encrypted, 'key', { mode: cryptoJs.mode.OFB }).toString(cryptoJs.enc.Utf8)).toEqual('Test');
  expect(cryptoJsWasm.AES.decrypt(encrypted, 'key', { mode: cryptoJsWasm.mode.OFB }).toString(cryptoJsWasm.enc.Utf8)).toEqual('Test');
});

test('testDecryptModeCTR', () => {
  const encrypted = cryptoJs.AES.encrypt('Test', 'key', { mode: cryptoJs.mode.CTR }).toString();
  expect(cryptoJs.AES.decrypt(encrypted, 'key', { mode: cryptoJs.mode.CTR }).toString(cryptoJs.enc.Utf8)).toEqual('Test');
  expect(cryptoJsWasm.AES.decrypt(encrypted, 'key', { mode: cryptoJsWasm.mode.CTR }).toString(cryptoJsWasm.enc.Utf8)).toEqual('Test');
});

test('testEncryptKeySize128', () => {
  expect(cryptoJsWasm.AES.encrypt('Test', key128, { iv: iv }).toString())
    .toEqual(cryptoJs.AES.encrypt('Test', key128, { iv: iv }).toString());
});

test('testEncryptKeySize192', () => {
  expect(cryptoJsWasm.AES.encrypt('Test', key192, { iv: iv }).toString())
    .toEqual(cryptoJs.AES.encrypt('Test', key192, { iv: iv }).toString());
});

test('testEncryptKeySize256', () => {
  expect(cryptoJsWasm.AES.encrypt('Test', key256, { iv: iv }).toString())
    .toEqual(cryptoJs.AES.encrypt('Test', key256, { iv: iv }).toString());
});

test('testDecryptKeySize128', () => {
  const encrypted = cryptoJs.AES.encrypt('Test', key128, { iv: iv }).toString();
  expect(cryptoJs.AES.decrypt(encrypted, key128, { iv: iv }).toString(cryptoJs.enc.Utf8)).toEqual('Test');
  expect(cryptoJsWasm.AES.decrypt(encrypted, key128, { iv: iv }).toString(cryptoJsWasm.enc.Utf8)).toEqual('Test');
});

test('testDecryptKeySize192', () => {
  const encrypted = cryptoJs.AES.encrypt('Test', key192, { iv: iv }).toString();
  expect(cryptoJs.AES.decrypt(encrypted, key192, { iv: iv }).toString(cryptoJs.enc.Utf8)).toEqual('Test');
  expect(cryptoJsWasm.AES.decrypt(encrypted, key192, { iv: iv }).toString(cryptoJsWasm.enc.Utf8)).toEqual('Test');
});

test('testDecryptKeySize256', () => {
  const encrypted = cryptoJs.AES.encrypt('Test', key256, { iv: iv }).toString();
  expect(cryptoJs.AES.decrypt(encrypted, key256, { iv: iv }).toString(cryptoJs.enc.Utf8)).toEqual('Test');
  expect(cryptoJsWasm.AES.decrypt(encrypted, key256, { iv: iv }).toString(cryptoJsWasm.enc.Utf8)).toEqual('Test');
});

test('testMultiPart', () => {
  let aes = cryptoJs.algo.AES.createEncryptor(key128, { iv: iv });
  let aesWasm = cryptoJsWasm.algo.AES.createEncryptor(key128, { iv: iv });
  let ciphertext1 = aes.process(data1);
  let ciphertext2 = aes.process(data2);
  let ciphertext3 = aes.process(data3);
  let ciphertext4 = aes.finalize();
  let ciphertextWasm1 = aesWasm.process(data1);
  let ciphertextWasm2 = aesWasm.process(data2);
  let ciphertextWasm3 = aesWasm.process(data3);
  let ciphertextWasm4 = aesWasm.finalize();
  let ciphertext = ciphertext1.concat(ciphertext2).concat(ciphertext3).concat(ciphertext4);
  let ciphertextWasm = ciphertextWasm1.concat(ciphertextWasm2).concat(ciphertextWasm3).concat(ciphertextWasm4);
  expect(ciphertext1.toString()).toEqual(ciphertextWasm1.toString());
  expect(ciphertext2.toString()).toEqual(ciphertextWasm2.toString());
  expect(ciphertext3.toString()).toEqual(ciphertextWasm3.toString());
  expect(ciphertext4.toString()).toEqual(ciphertextWasm4.toString());
  expect(ciphertext.toString()).toEqual(ciphertextWasm.toString());
  expect(ciphertext.toString(cryptoJs.enc.Base64)).toEqual(cryptoJs.AES.encrypt(data,
    key128, { iv: iv }).toString());
  expect(ciphertextWasm.toString(cryptoJsWasm.enc.Base64)).toEqual(cryptoJsWasm.AES.encrypt(data,
    key128, { iv: iv }).toString());
});

test('testMultiPartECB', () => {
  let aes = cryptoJs.algo.AES.createEncryptor(key128, { mode: cryptoJs.mode.ECB });
  let aesWasm = cryptoJsWasm.algo.AES.createEncryptor(key128, { mode: cryptoJsWasm.mode.ECB });
  let ciphertext1 = aes.process(data1);
  let ciphertext2 = aes.process(data2);
  let ciphertext3 = aes.process(data3);
  let ciphertext4 = aes.finalize();
  let ciphertextWasm1 = aesWasm.process(data1);
  let ciphertextWasm2 = aesWasm.process(data2);
  let ciphertextWasm3 = aesWasm.process(data3);
  let ciphertextWasm4 = aesWasm.finalize();
  let ciphertext = ciphertext1.concat(ciphertext2).concat(ciphertext3).concat(ciphertext4);
  let ciphertextWasm = ciphertextWasm1.concat(ciphertextWasm2).concat(ciphertextWasm3).concat(ciphertextWasm4);
  expect(ciphertext1.toString()).toEqual(ciphertextWasm1.toString());
  expect(ciphertext2.toString()).toEqual(ciphertextWasm2.toString());
  expect(ciphertext3.toString()).toEqual(ciphertextWasm3.toString());
  expect(ciphertext4.toString()).toEqual(ciphertextWasm4.toString());
  expect(ciphertext.toString()).toEqual(ciphertextWasm.toString());
  expect(ciphertext.toString(cryptoJs.enc.Base64)).toEqual(cryptoJs.AES.encrypt(data,
    key128, { mode: cryptoJs.mode.ECB }).toString());
  expect(ciphertextWasm.toString(cryptoJsWasm.enc.Base64)).toEqual(cryptoJsWasm.AES.encrypt(data,
    key128, { mode: cryptoJsWasm.mode.ECB }).toString());
});

test('testMultiPartCFB', () => {
  let aes = cryptoJs.algo.AES.createEncryptor(key128, { iv: iv, mode: cryptoJs.mode.CFB });
  let aesWasm = cryptoJsWasm.algo.AES.createEncryptor(key128, { iv: iv, mode: cryptoJsWasm.mode.CFB });
  let ciphertext1 = aes.process(data1);
  let ciphertext2 = aes.process(data2);
  let ciphertext3 = aes.process(data3);
  let ciphertext4 = aes.finalize();
  let ciphertextWasm1 = aesWasm.process(data1);
  let ciphertextWasm2 = aesWasm.process(data2);
  let ciphertextWasm3 = aesWasm.process(data3);
  let ciphertextWasm4 = aesWasm.finalize();
  let ciphertext = ciphertext1.concat(ciphertext2).concat(ciphertext3).concat(ciphertext4);
  let ciphertextWasm = ciphertextWasm1.concat(ciphertextWasm2).concat(ciphertextWasm3).concat(ciphertextWasm4);
  expect(ciphertext1.toString()).toEqual(ciphertextWasm1.toString());
  expect(ciphertext2.toString()).toEqual(ciphertextWasm2.toString());
  expect(ciphertext3.toString()).toEqual(ciphertextWasm3.toString());
  expect(ciphertext4.toString()).toEqual(ciphertextWasm4.toString());
  expect(ciphertext.toString()).toEqual(ciphertextWasm.toString());
  expect(ciphertext.toString(cryptoJs.enc.Base64)).toEqual(cryptoJs.AES.encrypt(data,
    key128, { iv: iv, mode: cryptoJs.mode.CFB }).toString());
  expect(ciphertextWasm.toString(cryptoJsWasm.enc.Base64)).toEqual(cryptoJsWasm.AES.encrypt(data,
    key128, { iv: iv, mode: cryptoJsWasm.mode.CFB }).toString());
});

test('testMultiPartOFB', () => {
  let aes = cryptoJs.algo.AES.createEncryptor(key128, { iv: iv, mode: cryptoJs.mode.OFB });
  let aesWasm = cryptoJsWasm.algo.AES.createEncryptor(key128, { iv: iv, mode: cryptoJsWasm.mode.OFB });
  let ciphertext1 = aes.process(data1);
  let ciphertext2 = aes.process(data2);
  let ciphertext3 = aes.process(data3);
  let ciphertext4 = aes.finalize();
  let ciphertextWasm1 = aesWasm.process(data1);
  let ciphertextWasm2 = aesWasm.process(data2);
  let ciphertextWasm3 = aesWasm.process(data3);
  let ciphertextWasm4 = aesWasm.finalize();
  let ciphertext = ciphertext1.concat(ciphertext2).concat(ciphertext3).concat(ciphertext4);
  let ciphertextWasm = ciphertextWasm1.concat(ciphertextWasm2).concat(ciphertextWasm3).concat(ciphertextWasm4);
  expect(ciphertext1.toString()).toEqual(ciphertextWasm1.toString());
  expect(ciphertext2.toString()).toEqual(ciphertextWasm2.toString());
  expect(ciphertext3.toString()).toEqual(ciphertextWasm3.toString());
  expect(ciphertext4.toString()).toEqual(ciphertextWasm4.toString());
  expect(ciphertext.toString()).toEqual(ciphertextWasm.toString());
  expect(ciphertext.toString(cryptoJs.enc.Base64)).toEqual(cryptoJs.AES.encrypt(data,
    key128, { iv: iv, mode: cryptoJs.mode.OFB }).toString());
  expect(ciphertextWasm.toString(cryptoJsWasm.enc.Base64)).toEqual(cryptoJsWasm.AES.encrypt(data,
    key128, { iv: iv, mode: cryptoJsWasm.mode.OFB }).toString());
});

test('testMultiPartCTR', () => {
  let aes = cryptoJs.algo.AES.createEncryptor(key128, { iv: iv, mode: cryptoJs.mode.CTR });
  let aesWasm = cryptoJsWasm.algo.AES.createEncryptor(key128, { iv: iv, mode: cryptoJsWasm.mode.CTR });
  let ciphertext1 = aes.process(data1);
  let ciphertext2 = aes.process(data2);
  let ciphertext3 = aes.process(data3);
  let ciphertext4 = aes.finalize();
  let ciphertextWasm1 = aesWasm.process(data1);
  let ciphertextWasm2 = aesWasm.process(data2);
  let ciphertextWasm3 = aesWasm.process(data3);
  let ciphertextWasm4 = aesWasm.finalize();
  let ciphertext = ciphertext1.concat(ciphertext2).concat(ciphertext3).concat(ciphertext4);
  let ciphertextWasm = ciphertextWasm1.concat(ciphertextWasm2).concat(ciphertextWasm3).concat(ciphertextWasm4);
  expect(ciphertext1.toString()).toEqual(ciphertextWasm1.toString());
  expect(ciphertext2.toString()).toEqual(ciphertextWasm2.toString());
  expect(ciphertext3.toString()).toEqual(ciphertextWasm3.toString());
  expect(ciphertext4.toString()).toEqual(ciphertextWasm4.toString());
  expect(ciphertext.toString()).toEqual(ciphertextWasm.toString());
  expect(ciphertext.toString(cryptoJs.enc.Base64)).toEqual(cryptoJs.AES.encrypt(data,
    key128, { iv: iv, mode: cryptoJs.mode.CTR }).toString());
  expect(ciphertextWasm.toString(cryptoJsWasm.enc.Base64)).toEqual(cryptoJsWasm.AES.encrypt(data,
    key128, { iv: iv, mode: cryptoJsWasm.mode.CTR }).toString());
});