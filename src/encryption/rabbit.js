import {WordArray} from '../core/core.js';
import {StreamCipher} from '../core/cipher-core.js';
import {rabbitWasm} from './rabbit_bg';
import {wasmBytes} from './rabbit_wasm';
import {loadWasm} from '../utils/wasm-utils';

/**
 * Rabbit stream cipher algorithm
 */
export class RabbitAlgo extends StreamCipher {
  constructor(...args) {
    super(...args);

    this.blockSize = 128 / 32;
    this.ivSize = 64 / 32;
  }

  static wasm = null;

  static async loadWasm() {
    if (RabbitAlgo.wasm) {
      return RabbitAlgo.wasm;
    }

    RabbitAlgo.wasm = await loadWasm(wasmBytes);
    return RabbitAlgo.wasm;
  }

  async loadWasm() {
    return RabbitAlgo.loadWasm();
  }

  _doReset() {
  }

  _process(doFlush) {
    if (!RabbitAlgo.wasm) {
      throw new Error('WASM is not loaded yet. \'RabbitAlgo.loadWasm\' should be called first');
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
      rabbitWasm(RabbitAlgo.wasm).doProcess(nWordsReady, blockSize, this._key.words, ivWords, dataArray);
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
 *     var ciphertext = CryptoJS.Rabbit.encrypt(message, key, cfg);
 *     var plaintext  = CryptoJS.Rabbit.decrypt(ciphertext, key, cfg);
 */
export const Rabbit = StreamCipher._createHelper(RabbitAlgo);
