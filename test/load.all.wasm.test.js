import C from '../src/index';

beforeAll(async () => {
  await C.loadAllWasm();
});

describe('load-all0wasm-test', () => {
  test('testLoader', () => {
    expect(C.algo.MD5.loadWasm).not.toBeNull();
    expect(C.algo.SHA1.loadWasm).not.toBeNull();
    expect(C.algo.SHA3.loadWasm).not.toBeNull();
    expect(C.algo.SHA224.loadWasm).not.toBeNull();
    expect(C.algo.SHA256.loadWasm).not.toBeNull();
    expect(C.algo.SHA384.loadWasm).not.toBeNull();
    expect(C.algo.SHA512.loadWasm).not.toBeNull();
    expect(C.algo.RIPEMD160.loadWasm).not.toBeNull();
    expect(C.algo.EvpKDF.loadWasm).not.toBeNull();
    expect(C.algo.AES.loadWasm).not.toBeNull();
    expect(C.algo.Blowfish.loadWasm).not.toBeNull();
    expect(C.algo.DES.loadWasm).not.toBeNull();
    expect(C.algo.TripleDES.loadWasm).not.toBeNull();
    expect(C.algo.Rabbit.loadWasm).not.toBeNull();
    expect(C.algo.RabbitLegacy.loadWasm).not.toBeNull();
    expect(C.algo.RC4.loadWasm).not.toBeNull();
  });

  test('testHasherAndEncryption', () => {
    expect(C.MD5('').toString()).toBe('d41d8cd98f00b204e9800998ecf8427e');
    expect(C.SHA1('').toString()).toBe('da39a3ee5e6b4b0d3255bfef95601890afd80709');
    expect(C.SHA224('').toString()).toBe('d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f');
    expect(C.SHA256('').toString()).toBe('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
    expect(C.SHA384('').toString()).toBe('38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b');
    expect(C.SHA512('').toString()).toBe('cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e');
    expect(C.SHA3('', { outputLength: 512 }).toString()).toBe('0eab42de4c3ceb9235fc91acffe746b29c29a8c366b7c60e4e67c466f36a4304c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e');
    expect(C.RIPEMD160('').toString()).toBe('9c1185a5c5e9fc54612808977ee8f548b2258d31');

    // evpkdf
    expect(C.EvpKDF('password', 'saltsalt', { keySize: (256+128)/32 }).toString()).toBe('fdbdf3419fff98bdb0241390f62a9db35f4aba29d77566377997314ebfc709f20b5ca7b1081f94b1ac12e3c8ba87d05a');
    // aes
    expect(C.AES.encrypt(C.enc.Hex.parse('00112233445566778899aabbccddeeff'), C.enc.Hex.parse('000102030405060708090a0b0c0d0e0f'), {
      mode: C.mode.ECB,
      padding: C.pad.NoPadding
    }).ciphertext.toString()).toBe('69c4e0d86a7b0430d8cdb78070b4c55a');
    // blowfish
    expect(C.Blowfish.encrypt('Test',
      'pass',
      {
        salt: C.enc.Hex.parse('AA00000000000000'),
        hasher: C.algo.SHA256
      }).toString()).toBe('U2FsdGVkX1+qAAAAAAAAAKTIU8MPrBdH');
    // des
    expect(C.DES.encrypt(C.enc.Hex.parse('0000000000000000'), C.enc.Hex.parse('8000000000000000'), {
      mode: C.mode.ECB,
      padding: C.pad.NoPadding
    }).ciphertext.toString()).toBe('95a8d72813daa94d');
    // tripleDES
    expect(C.TripleDES.encrypt(C.enc.Hex.parse('0000000000000000'), C.enc.Hex.parse('800101010101010180010101010101018001010101010101'), {
      mode: C.mode.ECB,
      padding: C.pad.NoPadding
    }).ciphertext.toString()).toBe('95a8d72813daa94d');
    // rabbit
    expect(C.Rabbit.encrypt(C.enc.Hex.parse('00000000000000000000000000000000'), C.enc.Hex.parse('0053a6f94c9ff24598eb3e91e4378add'), {
      iv: C.enc.Hex.parse('0d74db42a91077de')
    }).ciphertext.toString())
      .toBe('75d186d6bc6905c64f1b2dfdd51f7bfc');
    // rabbitLegacy
    expect(C.RabbitLegacy.encrypt(C.enc.Hex.parse('00000000000000000000000000000000'), C.enc.Hex.parse('00000000000000000000000000000000'), {
      iv: C.enc.Hex.parse('0000000000000000')
    }).ciphertext.toString())
      .toBe('edb70567375dcd7cd89554f85e27a7c6');
    // rc4
    expect(C.RC4.encrypt(C.enc.Hex.parse('0000000000000000'), C.enc.Hex.parse('0123456789abcdef')).ciphertext.toString())
      .toBe('7494c2e7104b0879');
  });
});
