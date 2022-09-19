import {WordArray} from '../core/core.js';
import {BlockCipher} from '../core/cipher-core.js';
import {desWasm} from './des_bg';
import {wasmBytes} from './des_wasm';
import {loadWasm} from '../utils/wasm-utils';

// Permuted Choice 1 constants
const PC1 = [
  57, 49, 41, 33, 25, 17, 9, 1,
  58, 50, 42, 34, 26, 18, 10, 2,
  59, 51, 43, 35, 27, 19, 11, 3,
  60, 52, 44, 36, 63, 55, 47, 39,
  31, 23, 15, 7, 62, 54, 46, 38,
  30, 22, 14, 6, 61, 53, 45, 37,
  29, 21, 13, 5, 28, 20, 12, 4
];

// Permuted Choice 2 constants
const PC2 = [
  14, 17, 11, 24, 1, 5,
  3, 28, 15, 6, 21, 10,
  23, 19, 12, 4, 26, 8,
  16, 7, 27, 20, 13, 2,
  41, 52, 31, 37, 47, 55,
  30, 40, 51, 45, 33, 48,
  44, 49, 39, 56, 34, 53,
  46, 42, 50, 36, 29, 32
];

// Cumulative bit shift constants
const BIT_SHIFTS = [1, 2, 4, 6, 8, 10, 12, 14, 15, 17, 19, 21, 23, 25, 27, 28];

/**
 * DES block cipher algorithm.
 */
export class DESAlgo extends BlockCipher {
  static get keySize() {
    return 64 / 32;
  }

  static get ivSize() {
    return 64 / 32;
  }

  static get blockSize() {
    return 64 / 32;
  }

  constructor(...args) {
    super(...args);

    this.keySize = 64 / 32;
    this.ivSize = 64 / 32;
    this.blockSize = 64 / 32;
  }

  static wasm = null;

  static async loadWasm() {
    if (DESAlgo.wasm) {
      return DESAlgo.wasm;
    }

    DESAlgo.wasm = await loadWasm(wasmBytes);
    return DESAlgo.wasm;
  }

  async loadWasm() {
    return DESAlgo.loadWasm();
  }

  _doReset() {
    // Shortcuts
    const key = this._key;
    const keyWords = key.words;

    // Select 56 bits according to PC1
    const keyBits = [];
    for (let i = 0; i < 56; i++) {
      const keyBitPos = PC1[i] - 1;
      keyBits[i] = (keyWords[keyBitPos >>> 5] >>> (31 - (keyBitPos % 32))) & 1;
    }

    // Assemble 16 subkeys
    this._subKeys = [];
    const subKeys = this._subKeys;
    for (let nSubKey = 0; nSubKey < 16; nSubKey++) {
      // Create subkey
      subKeys[nSubKey] = [];
      const subKey = subKeys[nSubKey];

      // Shortcut
      const bitShift = BIT_SHIFTS[nSubKey];

      // Select 48 bits according to PC2
      for (let i = 0; i < 24; i++) {
        // Select from the left 28 key bits
        subKey[(i / 6) | 0] |= keyBits[((PC2[i] - 1) + bitShift) % 28] << (31 - (i % 6));

        // Select from the right 28 key bits
        subKey[4 + ((i / 6) | 0)]
          |= keyBits[28 + (((PC2[i + 24] - 1) + bitShift) % 28)]
          << (31 - (i % 6));
      }

      // Since each subkey is applied to an expanded 32-bit input,
      // the subkey can be broken into 8 values scaled to 32-bits,
      // which allows the key to be used without expansion
      subKey[0] = (subKey[0] << 1) | (subKey[0] >>> 31);
      for (let i = 1; i < 7; i++) {
        subKey[i] >>>= ((i - 1) * 4 + 3);
      }
      subKey[7] = (subKey[7] << 5) | (subKey[7] >>> 27);
    }

    // Compute inverse subkeys
    this._invSubKeys = [];
    const invSubKeys = this._invSubKeys;
    for (let i = 0; i < 16; i++) {
      invSubKeys[i] = subKeys[15 - i];
    }
  }

  _process(doFlush) {
    if (!DESAlgo.wasm) {
      throw new Error('WASM is not loaded yet. \'DESAlgo.loadWasm\' should be called first');
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
      const ivWords = this.cfg.iv ? this.cfg.iv.words : '';
      // Perform concrete-algorithm logic
      if (this._xformMode == this._ENC_XFORM_MODE) {
        if (this.modeProcessBlock != undefined) {
          this.modeProcessBlock = desWasm(DESAlgo.wasm).doEncrypt(this.cfg.mode._name, nWordsReady, blockSize, this.modeProcessBlock, dataArray, this._key.words);
        } else {
          this.modeProcessBlock = desWasm(DESAlgo.wasm).doEncrypt(this.cfg.mode._name, nWordsReady, blockSize, ivWords, dataArray, this._key.words);
        }
      } else /* if (this._xformMode == this._DEC_XFORM_MODE) */ {
        if (this.modeProcessBlock != undefined) {
          this.modeProcessBlock = desWasm(DESAlgo.wasm).doDecrypt(this.cfg.mode._name, nWordsReady, blockSize, this.modeProcessBlock, dataArray, this._key.words);
        } else {
          this.modeProcessBlock = desWasm(DESAlgo.wasm).doDecrypt(this.cfg.mode._name, nWordsReady, blockSize, ivWords, dataArray, this._key.words);
        }
      }
      dataWords = Array.from(dataArray);
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
 *     const ciphertext = CryptoJSW.DES.encrypt(message, key, cfg);
 *     const plaintext  = CryptoJSW.DES.decrypt(ciphertext, key, cfg);
 */
export const DES = BlockCipher._createHelper(DESAlgo);

/**
 * Triple-DES block cipher algorithm.
 */
export class TripleDESAlgo extends BlockCipher {
  static get keySize() {
    return 192 / 32;
  }

  static get ivSize() {
    return 64 / 32;
  }

  static get blockSize() {
    return 64 / 32;
  }

  static async loadWasm() {
    return DESAlgo.loadWasm();
  }

  async loadWasm() {
    return TripleDESAlgo.loadWasm();
  }

  constructor(...args) {
    super(...args);

    this.keySize = 192 / 32;
    this.ivSize = 64 / 32;
    this.blockSize = 64 / 32;
  }

  /**
   * do nothing
   * @private
   */
  _doReset() {}

  _process(doFlush) {
    if (!DESAlgo.wasm) {
      throw new Error('WASM is not loaded yet. \'TripleDESAlgo.loadWasm\' should be called first');
    }
    let processedWords;

    // Shortcuts
    const data = this._data;
    let dataWords = data.words;
    const dataSigBytes = data.sigBytes;
    const blockSize = this.blockSize;
    const blockSizeBytes = blockSize * 4;
    const key = this._key;
    const keyWords = key.words;

    // Make sure the key length is valid (64, 128 or >= 192 bit)
    if (keyWords.length !== 2 && keyWords.length !== 4 && keyWords.length < 6) {
      throw new Error('Invalid key length - 3DES requires the key length to be 64, 128, 192 or >192.');
    }

    // Extend the key according to the keying options defined in 3DES standard
    const key1 = keyWords.slice(0, 2);
    const key2 = keyWords.length < 4 ? keyWords.slice(0, 2) : keyWords.slice(2, 4);
    const key3 = keyWords.length < 6 ? keyWords.slice(0, 2) : keyWords.slice(4, 6);

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
      const dataArray = new Uint32Array(dataWords);
      const ivWords = this.cfg.iv ? this.cfg.iv.words : '';
      // Perform concrete-algorithm logic
      if (this._xformMode == this._ENC_XFORM_MODE) {
        if (this.modeProcessBlock != undefined) {
          this.modeProcessBlock = desWasm(DESAlgo.wasm).tripleEncrypt(this.cfg.mode._name, nWordsReady, blockSize, this.modeProcessBlock, dataArray, key1, key2, key3);
        } else {
          this.modeProcessBlock = desWasm(DESAlgo.wasm).tripleEncrypt(this.cfg.mode._name, nWordsReady, blockSize, ivWords, dataArray, key1, key2, key3);
        }
      } else /* if (this._xformMode == this._DEC_XFORM_MODE) */ {
        if (this.modeProcessBlock != undefined) {
          this.modeProcessBlock = desWasm(DESAlgo.wasm).tripleDecrypt(this.cfg.mode._name, nWordsReady, blockSize, this.modeProcessBlock, dataArray, key1, key2, key3);
        } else {
          this.modeProcessBlock = desWasm(DESAlgo.wasm).tripleDecrypt(this.cfg.mode._name, nWordsReady, blockSize, ivWords, dataArray, key1, key2, key3);
        }
      }
      dataWords = Array.from(dataArray);
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
 *     const ciphertext = CryptoJSW.TripleDES.encrypt(message, key, cfg);
 *     const plaintext  = CryptoJSW.TripleDES.decrypt(ciphertext, key, cfg);
 */
export const TripleDES = BlockCipher._createHelper(TripleDESAlgo);
