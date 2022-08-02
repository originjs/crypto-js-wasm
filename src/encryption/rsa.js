import { init, RsaPrivate, RsaPublic } from './rsa_bg.js';

// TODO: should extend AsymmetricCipher(class not created yet)
export class RSAAlgo {
  // TODO: add code for loading wasm
  static wasm = null;

  static async loadWasm() {
    if (RSAAlgo.wasm) {
      return RSAAlgo.wasm;
    }

    RSAAlgo.wasm = await init();
    return RSAAlgo.wasm;
  }

  async loadWasm() {
    return RSAAlgo.loadWasm();
  }

  /**
   * Instantiate a new object with given key file
   * @param path the input key file path
   * @param isPubIn true if the input key file is a public key file
   * @returns {RSAAlgo} a new instance of RSAAlgo
   */
  static async fromKeyFile(path, isPubIn = false) {
    if (RSAAlgo.wasm === null) {
      await init();
      RSAAlgo.wasm = true;
    }

    const { fs } = await import('fs');

    const keyContent = fs.readFileSync(path, {
      encoding: 'utf-8',
      flag: 'r'
    });
    return isPubIn
      ? new this(null, new RsaPublic(keyContent))
      : new this(new RsaPrivate(null, keyContent));
  }

  /**
   * Instantiate a new object with given key size
   * @param bits key size in bytes
   * @returns {RSAAlgo} a new instance of RSAAlgo
   */
  static async fromKeySize(bits) {
    if (RSAAlgo.wasm === null) {
      await init();
      RSAAlgo.wasm = true;
    }

    return new this(new RsaPrivate(bits));
  }

  constructor(privateKey, publicKey) {
    if (publicKey === undefined) {
      if (privateKey === undefined) {
        // create a new 1024 bit RSA key pair if no parameter is specified
        privateKey = new RsaPrivate(1024);
      }
      publicKey = new RsaPublic(privateKey.getPublicKeyPem());
    }
    this.RsaPrivate = privateKey ?? null;
    this.RsaPublic = publicKey;
  }

  /**
   * Encrypt the given message
   * @param {string | Uint8Array} msg the original message
   * @param {string} padding the padding scheme for rsa encryption
   * @returns {Uint8Array} the encrypted message
   */
  encrypt(msg, padding = 'OAEP') {
    return this.RsaPublic.encrypt(this.strToBytes(msg), padding);
  }

  /**
   * Decrypt the given message
   * @param {Uint8Array} msgEncrypted the encrypted message
   * @param {string} padding the padding scheme for rsa encryption
   * @returns {Uint8Array} the decrypted message
   */
  decrypt(msgEncrypted, padding = 'OAEP') {
    this.errorIfNoPrivateInstance();
    return this.RsaPrivate.decrypt(msgEncrypted, padding);
  }

  // TODO: only support Uint8Array for now. Consider adding support for string(base64)
  /**
   * RSA sign
   * @param {string | Uint8Array} dig the digest of the message
   * @param {string} padding the padding scheme for rsa encryption
   * @returns {Uint8Array} the rsa signature
   */
  sign(dig, padding = 'PSS') {
    this.errorIfNoPrivateInstance();
    return this.RsaPrivate.sign(dig, padding);
  }

  /**
   * Verify the given RSA signature
   * @param {Uint8Array} dig the digest of the message
   * @param {Uint8Array} sig the signature signed using private key
   * @param {string} padding the padding scheme for rsa encryption
   * @returns {boolean} true if signature is valid
   */
  verify(dig, sig, padding = 'PSS') {
    return this.RsaPublic.verify(dig, sig, padding);
  }

  async generateKeyFile(keyType = 'pairs', fileFmt = 'pem', fileName = 'key', dir = './keys') {
    this.errorIfInBrowser();
    switch (keyType) {
    case 'pairs':
      this.generateKeyFile('private', fileFmt, fileName, dir);
      this.generateKeyFile('public', fileFmt, fileName, dir);
      return;
    case 'private':
      this.errorIfNoPrivateInstance();
      break;
    case 'public':
      // set file name to pubkey if no file name specified
      // TODO: fileName default to be "key"?
      fileName = fileName == 'key' ? 'pubkey' : fileName;
      break;
    default:
      throw TypeError('wrong key type provided. Should be \'pairs\', \'private\' or \'public\'');
    }

    let keyPath = `${dir}/${fileName}.${fileFmt}`;

    // TODO: .der file cannot be verified by openssl
    // TODO: .der file key content is not TypedArray now
    // get key content based on fileFmt
    let keyContent = this.getKeyContent(keyType, fileFmt);
    if (fileFmt == 'der') {
      keyContent = Uint8Array.from(keyContent);
    }

    const { fs } = await import('fs');

    // create dir if not existed
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir);
    }

    // write key file
    fs.writeFile(keyPath, keyContent, err => {
      if (err) {
        throw err;
      }
      console.log(`Successfully generated private key file at ${keyPath}`);
    });
  }

  /**
   * Get current key type
   * @returns {string} key type
   */
  // TODO: unused
  getKeyType() {
    return RsaPrivate ? 'private' : 'public';
  }

  /**
   * Get key content based on key type
   * @param keyType the type of key files. Should be "private" or "public"
   * @param keyFmt the encoding scheme. Should be "pem" or "der"
   * @returns {*}
   */
  getKeyContent(keyType, keyFmt = 'pem') {
    if (keyType == 'private') {
      this.errorIfNoPrivateInstance();
      return this.RsaPrivate.getPrivateKeyContent(keyFmt);
    }

    if (keyType == 'public') {
      return this.RsaPublic.getPublicKeyContent(keyFmt);
    }

    throw TypeError('Key type should be private or public');
  }

  /**
   * String to Uint8Array
   * @param val
   * @returns {Uint8Array|*}
   */
  strToBytes(val) {
    if (typeof val === 'string') {
      let encoder = new TextEncoder();
      return encoder.encode(val);
    }

    return val;
  }

  /**
   * Throws if private key is not instantiated
   */
  errorIfNoPrivateInstance() {
    if (this.RsaPrivate === null) {
      throw TypeError('Private key has not benn instantiated');
    }
  }

  /**
   * Throws if node-only function is called in browser
   */
  errorIfInBrowser() {
    if (typeof window !== 'undefined' && typeof window.document !== 'undefined') {
      throw Error('This function is not supported in browser mode');
    }
  }
}

/**
 * Shortcut of RSAAlgo with an instantiated 1024 bits key pair
 * @name RSA
 * @type {RSAAlgo}
 *
 * @example
 *  // encrypt/decrypt
 *  const msg = "Secret";
 *  const msgEnc = RSA.encrypt(msg);
 *  const msgDec = RSA.decrypto(msgEnc);
 *
 *  // sign/verify
 *  const dig = createHash("sha256").update(msg).digest();
 *  const sig = RSA.sign(dig);
 *  const isVerified = RSA.verify(dig, sig);
 */
export const RSAPromise = RSAAlgo.fromKeySize(1024);
