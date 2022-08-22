/** @preserve
(c) 2012 by Cédric Mesnil. All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted
provided that the following conditions are met:

    - Redistributions of source code must retain the above copyright notice, this list of
    conditions and the following disclaimer.
    - Redistributions in binary form must reproduce the above copyright notice, this list
    of conditions and the following disclaimer in the documentation and/or other materials
    provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS
OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY
WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

import { Hasher, } from '../../core/hasher';
import {WordArray,} from '../../core/core.js';
import {ripemd160Wasm,} from './ripemd160_bg';
import {wasmBytes,} from './ripemd160_wasm';
import {loadWasm,} from '../../utils/wasm-utils';



/**
 * RIPEMD160 hash algorithm.
 */
export class RIPEMD160Algo extends Hasher {
  static wasm = null;
  static outputSize = 160 / 8;

  static async loadWasm() {
    if (RIPEMD160Algo.wasm) {
      return RIPEMD160Algo.wasm;
    }

    RIPEMD160Algo.wasm = await loadWasm(wasmBytes);
    return RIPEMD160Algo.wasm;
  }

  async loadWasm() {
    return RIPEMD160Algo.loadWasm();
  }

  _doReset() {
    this._hash = new WordArray([0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0,]);
  }

  _process(doFlush) {
    if (!RIPEMD160Algo.wasm) {
      throw new Error('WASM is not loaded yet. \'RIPEMD160Algo.loadWasm\' should be called first');
    }
    let processedWords;

    // Shortcuts
    const data = this._data;
    let dataWords = data.words;
    const dataSigBytes = data.sigBytes;
    const blockSize = this.blockSize;
    const blockSizeBytes = blockSize * 4;
    let H = this._hash.words;

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
      const H_Array = new Uint32Array(H);
      // Perform concrete-algorithm logic
      ripemd160Wasm(RIPEMD160Algo.wasm).doProcess(nWordsReady, blockSize, dataWords, H_Array);
      this._hash.words = Array.from(H_Array);
      // Remove processed words
      processedWords = dataWords.splice(0, nWordsReady);
      // write data back to this._data
      this._data.words = dataWords;
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
    dataWords[(((nBitsLeft + 64) >>> 9) << 4) + 14] = (
      (((nBitsTotal << 8) | (nBitsTotal >>> 24)) & 0x00ff00ff)
        | (((nBitsTotal << 24) | (nBitsTotal >>> 8)) & 0xff00ff00)
    );
    data.sigBytes = (dataWords.length + 1) * 4;

    // Hash final blocks
    this._process();

    // Shortcuts
    const hash = this._hash;
    const H = hash.words;

    // Swap endian
    for (let i = 0; i < 5; i++) {
      // Shortcut
      const H_i = H[i];

      // Swap
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
 *     const hash = CryptoJSW.RIPEMD160('message');
 *     const hash = CryptoJSW.RIPEMD160(wordArray);
 */
export const RIPEMD160 = Hasher._createHelper(RIPEMD160Algo);

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
 *     const hmac = CryptoJSW.HmacRIPEMD160(message, key);
 */
export const HmacRIPEMD160 = Hasher._createHmacHelper(RIPEMD160Algo);
