import { WordArray, } from '../../core/core.js';
import { SHA256Algo, } from './sha256.js';

/**
 * SHA-224 hash algorithm.
 */
export class SHA224Algo extends SHA256Algo {
  static outputSize = 224 / 8;

  static async loadWasm() {
    return SHA256Algo.loadWasm();
  }

  async loadWasm() {
    return SHA224Algo.loadWasm();
  }

  _doReset() {
    this._hash = new WordArray([
      0xc1059ed8,
      0x367cd507,
      0x3070dd17,
      0xf70e5939,
      0xffc00b31,
      0x68581511,
      0x64f98fa7,
      0xbefa4fa4,
    ]);
  }

  _doFinalize() {
    const hash = super._doFinalize.call(this);

    hash.sigBytes -= 4;

    return hash;
  }
}

/**
 * Shortcut function to the hasher's object interface.
 *
 * @param {WordArray|string} message The message to hash.
 *
 * @return {WordArray} The hash.
 *
 * @static
 *
 * @example
 *
 *     const hash = CryptoJSW.SHA224('message');
 *     const hash = CryptoJSW.SHA224(wordArray);
 */
export const SHA224 = SHA256Algo._createHelper(SHA224Algo);

/**
 * Shortcut function to the HMAC's object interface.
 *
 * @param {WordArray|string} message The message to hash.
 * @param {WordArray|string} key The secret key.
 *
 * @return {WordArray} The HMAC.
 *
 * @static
 *
 * @example
 *
 *     const hmac = CryptoJSW.HmacSHA224(message, key);
 */
export const HmacSHA224 = SHA256Algo._createHmacHelper(SHA224Algo);
