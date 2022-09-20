import { WordArray } from '../../core/core.js';
import { X64Word } from '../../core/x64-core.js';
import { Hasher } from '../../core/hasher';
import { wasmBytes } from './sha3_wasm';
import { sha3Wasm } from './sha3_bg';
import { loadWasm } from '../../utils/wasm-utils';

/**
 * SHA-3 hash algorithm.
 */
export class SHA3Algo extends Hasher {
  static wasm = null;

  static async loadWasm() {
    if (SHA3Algo.wasm) {
      return SHA3Algo.wasm;
    }

    SHA3Algo.wasm = await loadWasm(wasmBytes);
    return SHA3Algo.wasm;
  }

  async loadWasm() {
    return SHA3Algo.loadWasm();
  }

  constructor(cfg) {
    /**
     * Configuration options.
     *
     * @property {number} outputLength
     *   The desired number of bits in the output hash.
     *   Only values permitted are: 224, 256, 384, 512.
     *   Default: 512
     */
    super(Object.assign(
      { outputLength: 512 },
      cfg
    ));
  }

  _doReset() {
    this._state = [];
    const state = this._state;
    for (let i = 0; i < 25; i++) {
      state[i] = new X64Word();
    }

    this.blockSize = (1600 - 2 * this.cfg.outputLength) / 32;
  }

  _process(doFlush) {
    if (!SHA3Algo.wasm) {
      throw new Error('WASM is not loaded yet. \'SHA3Algo.loadWasm\' should be called first');
    }
    // Shortcuts
    const data = this._data;
    const dataWords = data.words;
    const dataSigBytes = data.sigBytes;
    const blockSize = this.blockSize;

    const stateData = new Uint32Array(50);

    for (let i = 0; i < 25; i++) {
      stateData[i * 2] = this._state[i].high;
      stateData[i * 2 + 1] = this._state[i].low;
    }

    for (let i = 0; i < dataWords.length;i++) {
      if (!dataWords[i]) {
        dataWords[i] = 0;
      }
    }
    const nWordsReady = sha3Wasm(SHA3Algo.wasm).doCrypt(doFlush ? 1 : 0, dataWords, dataSigBytes, blockSize, stateData, this._minBufferSize);
    // Count bytes ready
    const nBytesReady = Math.min(nWordsReady * 4, dataSigBytes);

    for (let i = 0; i < 25; i++) {
      this._state[i].high = stateData[i * 2];
      this._state[i].low = stateData[i * 2 + 1];
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
    const nBitsLeft = data.sigBytes * 8;
    const blockSizeBits = this.blockSize * 32;

    // Add padding
    dataWords[nBitsLeft >>> 5] |= 0x1 << (24 - nBitsLeft % 32);
    dataWords[((Math.ceil((nBitsLeft + 1) / blockSizeBits) * blockSizeBits) >>> 5) - 1] |= 0x80;
    data.sigBytes = dataWords.length * 4;

    // Hash final blocks
    this._process();

    // Shortcuts
    const state = this._state;
    const outputLengthBytes = this.cfg.outputLength / 8;
    const outputLengthLanes = outputLengthBytes / 8;

    // Squeeze
    const hashWords = [];
    for (let i = 0; i < outputLengthLanes; i++) {
      // Shortcuts
      const lane = state[i];
      let laneMsw = lane.high;
      let laneLsw = lane.low;

      // Swap endian
      laneMsw = (((laneMsw << 8) | (laneMsw >>> 24)) & 0x00ff00ff)
        | (((laneMsw << 24) | (laneMsw >>> 8)) & 0xff00ff00);
      laneLsw = (((laneLsw << 8) | (laneLsw >>> 24)) & 0x00ff00ff)
        | (((laneLsw << 24) | (laneLsw >>> 8)) & 0xff00ff00);

      // Squeeze state to retrieve hash
      hashWords.push(laneLsw);
      hashWords.push(laneMsw);
    }

    // Return final computed hash
    return new WordArray(hashWords, outputLengthBytes);
  }

  clone() {
    const clone = super.clone.call(this);

    clone._state = this._state.slice(0);
    const state = clone._state;
    for (let i = 0; i < 25; i++) {
      state[i] = state[i].clone();
    }

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
 *     const hash = CryptoJSW.SHA3('message');
 *     const hash = CryptoJSW.SHA3(wordArray);
 */
export const SHA3 = Hasher._createHelper(SHA3Algo);

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
 *     const hmac = CryptoJSW.HmacSHA3(message, key);
 */
export const HmacSHA3 = Hasher._createHmacHelper(SHA3Algo);
