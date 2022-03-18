import {WordArray} from '../../core/core';
import {Hasher} from '../../core/hasher';
import {wasmBytes} from './sha1_wasm';
import {loadWasm} from '../../utils/wasm-utils';
import {sha1Wasm} from './sha1_bg';

/**
 * SHA-1 hash algorithm.
 */
export class SHA1Algo extends Hasher {
  static wasm = null;

  static async loadWasm() {
    if (SHA1Algo.wasm) {
      return SHA1Algo.wasm;
    }

    SHA1Algo.wasm = await loadWasm(wasmBytes);
    return SHA1Algo.wasm;
  }

  async loadWasm() {
    return SHA1Algo.loadWasm();
  }

  _doReset() {
    this._hash = new WordArray([
      0x67452301,
      0xefcdab89,
      0x98badcfe,
      0x10325476,
      0xc3d2e1f0
    ]);
  }

  _process(doFlush) {
    if (!SHA1Algo.wasm) {
      throw new Error('WASM is not loaded yet. \'SHA1Algo.loadWasm\' should be called first');
    }
    // Shortcuts
    const data = this._data;
    const dataWords = data.words;
    const dataSigBytes = data.sigBytes;
    const blockSize = this.blockSize;

    const H = this._hash.words;
    const H_array = new Uint32Array(5);
    H_array[0] = H[0];
    H_array[1] = H[1];
    H_array[2] = H[2];
    H_array[3] = H[3];
    H_array[4] = H[4];

    const nWordsReady = sha1Wasm(SHA1Algo.wasm).doCrypt(doFlush ? 1 : 0, H_array, dataWords, dataSigBytes, blockSize, this._minBufferSize);
    // Count bytes ready
    const nBytesReady = Math.min(nWordsReady * 4, dataSigBytes);

    H[0] = H_array[0];
    H[1] = H_array[1];
    H[2] = H_array[2];
    H[3] = H_array[3];
    H[4] = H_array[4];

    let processedWords;
    if (nWordsReady) {
      processedWords = dataWords.splice(0, nWordsReady);
      data.sigBytes -= nBytesReady;
    }

    // Return processed words
    return new WordArray(processedWords, nBytesReady);
  }

  _doFinalize() {
    // Shortcuts
    const data = this._data;
    const dataWords = data.words;

    const nBitsTotal = this._nDataBytes * 8;
    const nBitsLeft = data.sigBytes * 8;

    // Add padding
    dataWords[nBitsLeft >>> 5] |= 0x80 << (24 - (nBitsLeft % 32));
    dataWords[(((nBitsLeft + 64) >>> 9) << 4) + 14] = Math.floor(nBitsTotal / 0x100000000);
    dataWords[(((nBitsLeft + 64) >>> 9) << 4) + 15] = nBitsTotal;
    data.sigBytes = dataWords.length * 4;

    // Hash final blocks
    this._process();

    // Return final computed hash
    return this._hash;
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
 *     var hash = CryptoJS.SHA1('message');
 *     var hash = CryptoJS.SHA1(wordArray);
 */
export const SHA1 = Hasher._createHelper(SHA1Algo);

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
 *     var hmac = CryptoJS.HmacSHA1(message, key);
 */
export const HmacSHA1 = Hasher._createHmacHelper(SHA1Algo);
