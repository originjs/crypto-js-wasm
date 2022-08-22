import {WordArray,} from '../../core/core.js';
import {Hasher,} from '../../core/hasher';
import {loadWasm,} from '../../utils/wasm-utils';
import {wasmBytes,} from './sha256_wasm';
import {sha256Wasm,} from './sha256_bg';

// Initialization and round constants tables
const H = [1779033703, -1150833019, 1013904242, -1521486534, 1359893119, -1694144372, 528734635, 1541459225,];

/**
 * SHA-256 hash algorithm.
 */
export class SHA256Algo extends Hasher {
  static wasm = null;
  static outputSize = 256 / 8;

  static async loadWasm() {
    if (SHA256Algo.wasm) {
      return SHA256Algo.wasm;
    }

    SHA256Algo.wasm = await loadWasm(wasmBytes);
    return SHA256Algo.wasm;
  }

  async loadWasm() {
    return SHA256Algo.loadWasm();
  }

  _doReset() {
    this._hash = new WordArray(H.slice(0));
  }

  _process(doFlush) {
    if (!SHA256Algo.wasm) {
      throw new Error('WASM is not loaded yet. \'SHA256Algo.loadWasm\' should be called first');
    }
    // Shortcuts
    const data = this._data;
    const dataWords = data.words;
    const dataSigBytes = data.sigBytes;
    const blockSize = this.blockSize;

    const H = this._hash.words;
    const H_array = new Uint32Array(8);
    for (let i = 0; i < 8; i++) {
      H_array[i] = H[i];
    }

    const nWordsReady = sha256Wasm(SHA256Algo.wasm).doCrypt(doFlush ? 1 : 0, dataWords, dataSigBytes, blockSize, H_array, this._minBufferSize);
    // Count bytes ready
    const nBytesReady = Math.min(nWordsReady * 4, dataSigBytes);

    for (let i = 0; i < 8; i++) {
      H[i] = H_array[i];
    }

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
 *     const hash = CryptoJSW.SHA256('message');
 *     const hash = CryptoJSW.SHA256(wordArray);
 */
export const SHA256 = Hasher._createHelper(SHA256Algo);

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
 *     const hmac = CryptoJSW.HmacSHA256(message, key);
 */
export const HmacSHA256 = Hasher._createHmacHelper(SHA256Algo);
