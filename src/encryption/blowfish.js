import { blowfishWasm } from './blowfish_bg';
import { WordArray } from '../core/core';
import { BlockCipher } from '../core/cipher-core.js';
import { loadWasm } from '../utils/wasm-utils';
import { wasmBytes } from './blowfish_wasm';

/**
 * Blowfish block cipher algorithm.
 */
export class BlowfishAlgo extends BlockCipher {
  static get keySize() {
    return 128 / 32;
  }

  static get ivSize() {
    return 64 / 32;
  }

  static get blockSize() {
    return 64 / 32;
  }

  static wasm = null;

  constructor(...args) {
    super(...args);

    this.keySize = 128 / 32;
    this.ivSize = 64 / 32;
    this.blockSize = 64 / 32;
  }

  static async loadWasm() {
    if (BlowfishAlgo.wasm) {
      return BlowfishAlgo.wasm;
    }

    BlowfishAlgo.wasm = await loadWasm(wasmBytes);
    return BlowfishAlgo.wasm;
  }

  async loadWasm() {
    return BlowfishAlgo.loadWasm();
  }

  _doReset() {
    // Skip reset of nRounds has been set before and key did not change
    if (this._keyPriorReset === this._key) {
      return;
    }

    // Shortcuts
    const key = this._keyPriorReset = this._key;
    const keyWords = key.words;
    const keySize = key.sigBytes / 4;

    //Initialization pbox and sbox
    const ctx = Array.from(blowfishWasm(BlowfishAlgo.wasm).blowfishInit(keyWords, keySize));
    this.pbox = ctx.splice(0, 18);
    this.sbox = [];
    for (let i = 0; i < 4; i++) {
      this.sbox[i] = ctx.splice(0, 256);
    }
  }

  _process(doFlush) {
    if (!BlowfishAlgo.wasm) {
      throw new Error('WASM is not loaded yet. \'BlowfishAlgo.loadWasm\' should be called first');
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
      let s = [];
      for (let i = 0; i < 4; i++) {
        s.push.apply(s, this.sbox[i]);
      }
      // Perform concrete-algorithm logic
      if (this._xformMode == this._ENC_XFORM_MODE) {
        if (this.modeProcessBlock != undefined) {
          this.modeProcessBlock = blowfishWasm(BlowfishAlgo.wasm).doEncrypt(this.cfg.mode._name, nWordsReady, blockSize, this.modeProcessBlock, dataArray, this.pbox, s);
        } else {
          this.modeProcessBlock = blowfishWasm(BlowfishAlgo.wasm).doEncrypt(this.cfg.mode._name, nWordsReady, blockSize, ivWords, dataArray, this.pbox, s);
        }
      } else /* if (this._xformMode == this._DEC_XFORM_MODE) */ {
        if (this.modeProcessBlock != undefined) {
          this.modeProcessBlock = blowfishWasm(BlowfishAlgo.wasm).doDecrypt(this.cfg.mode._name, nWordsReady, blockSize, this.modeProcessBlock, dataArray, this.pbox, s);
        } else {
          this.modeProcessBlock = blowfishWasm(BlowfishAlgo.wasm).doDecrypt(this.cfg.mode._name, nWordsReady, blockSize, ivWords, dataArray, this.pbox, s);
        }
      }
      dataWords = Array.from(dataArray);
      // Remove processed words
      processedWords = dataWords.splice(0, nWordsReady);
      data.words = dataWords;
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
 *     const ciphertext = CryptoJSW.Blowfish.encrypt(message, key, cfg);
 *     const plaintext  = CryptoJSW.Blowfish.decrypt(ciphertext, key, cfg);
 */
export const Blowfish = BlockCipher._createHelper(BlowfishAlgo);
