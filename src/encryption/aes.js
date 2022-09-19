import {aesWasm} from './aes_bg';
import {WordArray} from '../core/core';
import {BlockCipher} from '../core/cipher-core.js';
import {loadWasm} from '../utils/wasm-utils';
import {wasmBytes} from './aes_wasm';

/**
 * AES block cipher algorithm.
 */
export class AESAlgo extends BlockCipher {
  static get keySize() {
    return 256 / 32;
  }

  static wasm = null;

  constructor(...args) {
    super(...args);

    this.keySize = 256 / 32;
  }

  static async loadWasm() {
    if (AESAlgo.wasm) {
      return AESAlgo.wasm;
    }

    AESAlgo.wasm = await loadWasm(wasmBytes);
    return AESAlgo.wasm;
  }

  async loadWasm() {
    return AESAlgo.loadWasm();
  }

  _doReset() {
    // Skip reset of nRounds has been set before and key did not change
    if (this._nRounds && this._keyPriorReset === this._key) {
      return;
    }

    // Shortcuts
    const key = this._key;
    const keyWords = key.words;
    const keySize = key.sigBytes / 4;

    // Compute number of rounds
    this._nRounds = keySize + 6;

    this._keySchedule = aesWasm(AESAlgo.wasm).getKeySchedule(keySize, keyWords);
    this._invKeySchedule = aesWasm(AESAlgo.wasm).getInvKeySchedule(keySize, keyWords);
  }

  // eslint-disable-next-line no-dupe-class-members
  _process(doFlush) {
    if (!AESAlgo.wasm) {
      throw new Error('WASM is not loaded yet. \'AESAlgo.loadWasm\' should be called first');
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
          this.modeProcessBlock = aesWasm(AESAlgo.wasm).doEncrypt(this.cfg.mode._name, this._nRounds, nWordsReady, blockSize, this.modeProcessBlock, dataArray, this._keySchedule);
        } else {
          this.modeProcessBlock = aesWasm(AESAlgo.wasm).doEncrypt(this.cfg.mode._name, this._nRounds, nWordsReady, blockSize, ivWords, dataArray, this._keySchedule);
        }
      } else /* if (this._xformMode == this._DEC_XFORM_MODE) */ {
        if (this.modeProcessBlock != undefined) {
          this.modeProcessBlock = aesWasm(AESAlgo.wasm).doDecrypt(this.cfg.mode._name, this._nRounds, nWordsReady, blockSize, this.modeProcessBlock, dataArray, this._keySchedule, this._invKeySchedule);
        } else {
          this.modeProcessBlock = aesWasm(AESAlgo.wasm).doDecrypt(this.cfg.mode._name, this._nRounds, nWordsReady, blockSize, ivWords, dataArray, this._keySchedule, this._invKeySchedule);
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
 *     const ciphertext = CryptoJSW.AES.encrypt(message, key, cfg);
 *     const plaintext  = CryptoJSW.AES.decrypt(ciphertext, key, cfg);
 */
export const AES = BlockCipher._createHelper(AESAlgo);
