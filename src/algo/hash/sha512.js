import { Hasher } from '../../core/hasher';
import { WordArray } from '../../core/core.js';
import { X64Word, X64WordArray } from '../../core/x64-core.js';
import { loadWasm } from '../../utils/wasm-utils';
import { wasmBytes } from './sha512_wasm';
import { sha512Wasm } from './sha512_bg';

/**
 * SHA-512 hash algorithm.
 */
export class SHA512Algo extends Hasher {
  static wasm = null;
  static outputSize = 512 / 8;

  static async loadWasm() {
    if (SHA512Algo.wasm) {
      return SHA512Algo.wasm;
    }

    SHA512Algo.wasm = await loadWasm(wasmBytes);
    return SHA512Algo.wasm;
  }

  async loadWasm() {
    return SHA512Algo.loadWasm();
  }

  constructor() {
    super();

    this.blockSize = 1024 / 32;
  }

  _doReset() {
    this._hash = new X64WordArray([
      new X64Word(0x6a09e667, 0xf3bcc908),
      new X64Word(0xbb67ae85, 0x84caa73b),
      new X64Word(0x3c6ef372, 0xfe94f82b),
      new X64Word(0xa54ff53a, 0x5f1d36f1),
      new X64Word(0x510e527f, 0xade682d1),
      new X64Word(0x9b05688c, 0x2b3e6c1f),
      new X64Word(0x1f83d9ab, 0xfb41bd6b),
      new X64Word(0x5be0cd19, 0x137e2179)
    ]);
  }

  _process(doFlush) {
    if (!SHA512Algo.wasm) {
      throw new Error('WASM is not loaded yet. \'SHA512Algo.loadWasm\' should be called first');
    }
    let processedWords;

    // Shortcuts
    const data = this._data;
    const dataWords = data.words;
    const dataSigBytes = data.sigBytes;
    const blockSize = this.blockSize;
    const blockSizeBytes = blockSize * 4;

    // Count blocks ready
    let nBlocksReady = dataSigBytes / blockSizeBytes;
    if (doFlush) {
      // Round up to include partial blocks
      nBlocksReady = Math.ceil(nBlocksReady);
    } else {
      // Round down to include only full blocks,
      // less the number of blocks that must remain in the buffer
      nBlocksReady = Math.max((nBlocksReady | 0) - this._minBufferSize, 0);
    }

    // Count words ready
    const nWordsReady = nBlocksReady * blockSize;

    // Count bytes ready
    const nBytesReady = Math.min(nWordsReady * 4, dataSigBytes);

    // Process blocks
    if (nWordsReady) {
      const H = this._hash.words;
      const H_array = new Uint32Array(16);
      for (let i = 0; i < 8; i++) {
        H_array[i * 2] = H[i].high;
        H_array[i * 2 + 1] = H[i].low;
      }
      // Perform concrete-algorithm logic
      sha512Wasm(SHA512Algo.wasm).doCrypt(nWordsReady, blockSize, dataWords, H_array);
      for (let i = 0; i < 8; i++) {
        H[i].high = H_array[i * 2];
        H[i].low = H_array[i * 2 + 1];
      }
      // Remove processed words
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
    dataWords[(((nBitsLeft + 128) >>> 10) << 5) + 30] = Math.floor(nBitsTotal / 0x100000000);
    dataWords[(((nBitsLeft + 128) >>> 10) << 5) + 31] = nBitsTotal;
    data.sigBytes = dataWords.length * 4;

    // Hash final blocks
    this._process();

    // Convert hash to 32-bit word array before returning
    const hash = this._hash.toX32();

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
 *     const hash = CryptoJSW.SHA512('message');
 *     const hash = CryptoJSW.SHA512(wordArray);
 */
export const SHA512 = Hasher._createHelper(SHA512Algo);

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
 *     const hmac = CryptoJSW.HmacSHA512(message, key);
 */
export const HmacSHA512 = Hasher._createHmacHelper(SHA512Algo);
