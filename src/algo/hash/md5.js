import {WordArray} from '../../core/core.js';
import {Hasher} from '../../core/hasher';
import {loadWasm} from '../../utils/wasm-utils';
import {wasmBytes} from './md5_wasm';
import {md5Wasm} from './md5_bg';

/**
 * MD5 hash algorithm.
 */
export class MD5Algo extends Hasher {
  static wasm = null;
  static outputSize = 128 / 8;

  static async loadWasm() {
    if (MD5Algo.wasm) {
      return MD5Algo.wasm;
    }

    MD5Algo.wasm = await loadWasm(wasmBytes);
    return MD5Algo.wasm;
  }

  async loadWasm() {
    return MD5Algo.loadWasm();
  }

  _doReset() {
    this._hash = new WordArray([
      0x67452301,
      0xefcdab89,
      0x98badcfe,
      0x10325476
    ]);
  }

  _process(doFlush) {
    if (!MD5Algo.wasm) {
      throw new Error('WASM is not loaded yet. \'MD5Algo.loadWasm\' should be called first');
    }
    // Shortcuts
    const data = this._data;
    const dataWords = data.words;
    const dataSigBytes = data.sigBytes;
    const blockSize = this.blockSize;

    const H = this._hash.words;
    const H_array = new Uint32Array(4);
    H_array[0] = H[0];
    H_array[1] = H[1];
    H_array[2] = H[2];
    H_array[3] = H[3];

    const nWordsReady = md5Wasm(MD5Algo.wasm).md5Process(doFlush ? 1 : 0, H_array, dataWords, dataSigBytes, blockSize, this._minBufferSize);
    // Count bytes ready
    const nBytesReady = Math.min(nWordsReady * 4, dataSigBytes);

    H[0] = H_array[0];
    H[1] = H_array[1];
    H[2] = H_array[2];
    H[3] = H_array[3];

    let processedWords;
    if (nWordsReady) {
      processedWords = dataWords.splice(0, nWordsReady);
      data.sigBytes -= nBytesReady;
    }

    // Return processed words
    return new WordArray(processedWords, nBytesReady);
  }

  /* eslint-ensable no-param-reassign */

  _doFinalize() {
    // Shortcuts
    const data = this._data;
    const dataWords = data.words;

    const nBitsTotal = this._nDataBytes * 8;
    const nBitsLeft = data.sigBytes * 8;

    // Add padding
    dataWords[nBitsLeft >>> 5] |= 0x80 << (24 - (nBitsLeft % 32));

    const nBitsTotalH = Math.floor(nBitsTotal / 0x100000000);
    const nBitsTotalL = nBitsTotal;
    dataWords[(((nBitsLeft + 64) >>> 9) << 4) + 15] = (
      (((nBitsTotalH << 8) | (nBitsTotalH >>> 24)) & 0x00ff00ff)
      | (((nBitsTotalH << 24) | (nBitsTotalH >>> 8)) & 0xff00ff00)
    );
    dataWords[(((nBitsLeft + 64) >>> 9) << 4) + 14] = (
      (((nBitsTotalL << 8) | (nBitsTotalL >>> 24)) & 0x00ff00ff)
      | (((nBitsTotalL << 24) | (nBitsTotalL >>> 8)) & 0xff00ff00)
    );

    data.sigBytes = (dataWords.length + 1) * 4;

    // Hash final blocks
    this._process();

    // Shortcuts
    const hash = this._hash;
    const H = hash.words;

    // Swap endian
    for (let i = 0; i < 4; i++) {
      // Shortcut
      const H_i = H[i];

      H[i] = (((H_i << 8) | (H_i >>> 24)) & 0x00ff00ff)
        | (((H_i << 24) | (H_i >>> 8)) & 0xff00ff00);
    }

    // Return final computed hash
    return hash;
  }

  clone() {
    const clone = super.clone.call(this);
    clone._hash = this._hash.clone();

    return clone;
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
 *     const hash = CryptoJSW.MD5('message');
 *     const hash = CryptoJSW.MD5(wordArray);
 */
export const MD5 = Hasher._createHelper(MD5Algo);

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
 *     const hmac = CryptoJSW.HmacMD5(message, key);
 */
export const HmacMD5 = Hasher._createHmacHelper(MD5Algo);
