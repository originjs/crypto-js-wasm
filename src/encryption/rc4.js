import {WordArray} from '../core/core.js';
import {StreamCipher} from '../core/cipher-core.js';
import {rc4Wasm} from './rc4_bg';
import {wasmBytes} from './rc4_wasm';
import {loadWasm} from '../utils/wasm-utils';

function generateKeystreamWord() {
  // Shortcuts
  const S = this._S;
  let i = this._i;
  let j = this._j;

  // Generate keystream word
  let keystreamWord = 0;
  for (let n = 0; n < 4; n++) {
    i = (i + 1) % 256;
    j = (j + S[i]) % 256;

    // Swap
    const t = S[i];
    S[i] = S[j];
    S[j] = t;

    keystreamWord |= S[(S[i] + S[j]) % 256] << (24 - n * 8);
  }

  // Update counters
  this._i = i;
  this._j = j;

  return keystreamWord;
}

/**
 * RC4 stream cipher algorithm.
 */
export class RC4Algo extends StreamCipher {
  static get keySize() {
    return 256 / 32;
  }

  static get ivSize() {
    return 0;
  }

  constructor(...args) {
    super(...args);

    this.keySize = 256 / 32;
    this.ivSize = 0;
  }

  static wasm = null;

  static async loadWasm() {
    if (RC4Algo.wasm) {
      return RC4Algo.wasm;
    }

    RC4Algo.wasm = await loadWasm(wasmBytes);
    return RC4Algo.wasm;
  }

  async loadWasm() {
    return RC4Algo.loadWasm();
  }

  _doReset() {
    // Shortcuts
    const key = this._key;
    const keyWords = key.words;
    const keySigBytes = key.sigBytes;

    // Init sbox
    this._S = [];
    const S = this._S;
    for (let i = 0; i < 256; i++) {
      S[i] = i;
    }

    // Key setup
    for (let i = 0, j = 0; i < 256; i++) {
      const keyByteIndex = i % keySigBytes;
      const keyByte = (keyWords[keyByteIndex >>> 2] >>> (24 - (keyByteIndex % 4) * 8)) & 0xff;

      j = (j + S[i] + keyByte) % 256;

      // Swap
      const t = S[i];
      S[i] = S[j];
      S[j] = t;
    }

    // Counters
    this._j = 0;
    this._i = this._j;
  }

  _process(doFlush) {
    if (!RC4Algo.wasm) {
      throw new Error('WASM is not loaded yet. \'RC4Algo.loadWasm\' should be called first');
    }
    let processedWords;

    // Shortcuts
    const data = this._data;
    let dataWords = data.words;
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
      if (dataWords.length < nWordsReady) {
        for (let i = dataWords.length; i < nWordsReady; i++) {
          dataWords[i] = 0;
        }
      }
      const dataArray = new Uint32Array(dataWords);
      let S = this._S;
      S[256] = this._i;
      S[257] = this._j;
      const S_Array = new Uint32Array(S);
      // Perform concrete-algorithm logic
      rc4Wasm(RC4Algo.wasm).doProcess(nWordsReady, blockSize, dataArray, S_Array);
      dataWords = Array.from(dataArray);
      S = Array.from(S_Array);
      this._S = S.slice(0, 256);
      this._i = S[256];
      this._j = S[257];
      // Remove processed words
      processedWords = dataWords.splice(0, nWordsReady);
      // write data back to this._data
      this._data.words = dataWords;
      data.sigBytes -= nBytesReady;
    }

    // Return processed words
    return new WordArray(processedWords, nBytesReady);
  }
}

/**
 * Shortcut functions to the cipher's object interface.
 *
 * @example
 *
 *     var ciphertext = CryptoJS.RC4.encrypt(message, key, cfg);
 *     var plaintext  = CryptoJS.RC4.decrypt(ciphertext, key, cfg);
 */
export const RC4 = StreamCipher._createHelper(RC4Algo);

/**
 * Modified RC4 stream cipher algorithm.
 */
export class RC4DropAlgo extends RC4Algo {
  constructor(...args) {
    super(...args);

    /**
     * Configuration options.
     *
     * @property {number} drop The number of keystream words to drop. Default 192
     */
    if (!this.cfg.drop) {
      Object.assign(this.cfg, { drop: 192 });
    }
  }

  _doReset() {
    super._doReset.call(this);

    // Drop
    for (let i = this.cfg.drop; i > 0; i--) {
      generateKeystreamWord.call(this);
    }
  }
}

/**
 * Shortcut functions to the cipher's object interface.
 *
 * @example
 *
 *     var ciphertext = CryptoJS.RC4Drop.encrypt(message, key, cfg);
 *     var plaintext  = CryptoJS.RC4Drop.decrypt(ciphertext, key, cfg);
 */
export const RC4Drop = StreamCipher._createHelper(RC4DropAlgo);
