import cryptoJs from 'crypto-js/crypto-js';
import cryptoJsWasm from '../../src/index.js';

beforeAll(async () => {
  await cryptoJsWasm.RabbitLegacy.loadWasm();
  await cryptoJsWasm.SHA256.loadWasm();
});

const iv = cryptoJs.enc.Hex.parse('08090a0b0c0d0e0f');
const data1 = cryptoJs.enc.Hex.parse('001122334455001122334455001122334455001122334455');
const data2 = cryptoJs.enc.Hex.parse('66778899aa');
const data3 = cryptoJs.enc.Hex.parse('bbccddeeff');
const data = cryptoJs.enc.Hex.parse('00112233445500112233445500112233445500112233445566778899aabbccddeeff');

test('testHelper', () => {
  expect(cryptoJsWasm.algo.RabbitLegacy.createEncryptor(cryptoJsWasm.SHA256('key')).finalize('Test').toString())
    .toEqual(cryptoJs.algo.RabbitLegacy.createEncryptor(cryptoJs.SHA256('key')).finalize('Test').toString());
  expect(cryptoJsWasm.lib.SerializableCipher.encrypt(cryptoJsWasm.algo.RabbitLegacy, 'Test', cryptoJsWasm.SHA256('key')).toString())
    .toEqual(cryptoJs.lib.SerializableCipher.encrypt(cryptoJs.algo.RabbitLegacy, 'Test', cryptoJs.SHA256('key')).toString());
});

test('testEncrypt', () => {
  expect(cryptoJsWasm.RabbitLegacy.encrypt('Test', cryptoJsWasm.SHA256('key')).toString()).toEqual(cryptoJs.RabbitLegacy.encrypt('Test', cryptoJs.SHA256('key')).toString());
  expect(cryptoJsWasm.RabbitLegacy.encrypt('Test', cryptoJsWasm.SHA256('key'), {iv: iv}).toString()).toEqual(cryptoJs.RabbitLegacy.encrypt('Test', cryptoJs.SHA256('key'), {iv: iv}).toString());
});

test('testDecrypt', () => {
  const encrypted = cryptoJs.RabbitLegacy.encrypt('Test', 'key').toString();
  expect(cryptoJs.RabbitLegacy.decrypt(encrypted, 'key').toString(cryptoJs.enc.Utf8)).toEqual('Test');
  expect(cryptoJsWasm.RabbitLegacy.decrypt(encrypted, 'key').toString(cryptoJsWasm.enc.Utf8)).toEqual('Test');
  const encryptedWithIv = cryptoJs.RabbitLegacy.encrypt('Test', 'key', {iv: iv}).toString();
  expect(cryptoJs.RabbitLegacy.decrypt(encryptedWithIv, 'key').toString(cryptoJs.enc.Utf8)).toEqual('Test');
  expect(cryptoJsWasm.RabbitLegacy.decrypt(encryptedWithIv, 'key').toString(cryptoJsWasm.enc.Utf8)).toEqual('Test');
});

test('testMultiPart', () => {
  let rabbit = cryptoJs.algo.RabbitLegacy.createEncryptor(cryptoJs.SHA256('key'), {iv: iv});
  let rabbitWasm = cryptoJsWasm.algo.RabbitLegacy.createEncryptor(cryptoJsWasm.SHA256('key'), {iv: iv});
  let ciphertext1 = rabbit.process(data1);
  let ciphertext2 = rabbit.process(data2);
  let ciphertext3 = rabbit.process(data3);
  let ciphertext4 = rabbit.finalize();
  let ciphertextWasm1 = rabbitWasm.process(data1);
  let ciphertextWasm2 = rabbitWasm.process(data2);
  let ciphertextWasm3 = rabbitWasm.process(data3);
  let ciphertextWasm4 = rabbitWasm.finalize();
  let ciphertext = ciphertext1.concat(ciphertext2).concat(ciphertext3).concat(ciphertext4);
  let ciphertextWasm = ciphertextWasm1.concat(ciphertextWasm2).concat(ciphertextWasm3).concat(ciphertextWasm4);
  expect(ciphertext1.toString()).toEqual(ciphertextWasm1.toString());
  expect(ciphertext2.toString()).toEqual(ciphertextWasm2.toString());
  expect(ciphertext3.toString()).toEqual(ciphertextWasm3.toString());
  expect(ciphertext4.toString()).toEqual(ciphertextWasm4.toString());
  expect(ciphertext.toString()).toEqual(ciphertextWasm.toString());
  expect(ciphertext.toString(cryptoJs.enc.Base64)).toEqual(cryptoJs.RabbitLegacy.encrypt(data, cryptoJs.SHA256('key'), {iv: iv}).toString());
  expect(ciphertextWasm.toString(cryptoJsWasm.enc.Base64)).toEqual(cryptoJsWasm.RabbitLegacy.encrypt(data, cryptoJsWasm.SHA256('key'), {iv: iv}).toString());
});