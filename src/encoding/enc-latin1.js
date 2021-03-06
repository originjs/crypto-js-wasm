import {
  WordArray
} from '../core/core.js';

/**
 * Latin1 encoding strategy.
 */
export const Latin1 = {
  /**
     * Converts a word array to a Latin1 string.
     *
     * @param {WordArray} wordArray The word array.
     *
     * @return {string} The Latin1 string.
     *
     * @static
     *
     * @example
     *
     *     const latin1String = CryptoJSW.enc.Latin1.stringify(wordArray);
     */
  stringify(wordArray) {
    // Shortcuts
    const {
      words,
      sigBytes
    } = wordArray;

    // Convert
    let latin1Chars = '';
    for (let i = 0; i < sigBytes; i++) {
      const byte = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
      latin1Chars += String.fromCharCode(byte);
    }

    return latin1Chars;
  },

  /**
     * Converts a Latin1 string to a word array.
     *
     * @param {string} latin1Str The Latin1 string.
     *
     * @return {WordArray} The word array.
     *
     * @static
     *
     * @example
     *
     *     const wordArray = CryptoJSW.enc.Latin1.parse(latin1String);
     */
  parse(latin1Str) {
    // Shortcut
    const latin1StrLength = latin1Str.length;

    // Convert
    const words = [];
    let word = 0;
    // const words = new Array(latin1StrLength >>> 2);
    for (let i = 0; i < latin1StrLength - latin1StrLength % 4; i++) {
      word |= (latin1Str.charCodeAt(i) & 0xff) << (24 - (i % 4) * 8);
      if (i % 4 == 3) {
        words[i >>> 2] = word;
        word = 0;
      }
    }
    for (let i = latin1StrLength - latin1StrLength % 4; i < latin1StrLength;i++) {
      words[i >>> 2] |= (latin1Str.charCodeAt(i) & 0xff) << (24 - (i % 4) * 8);
    }

    return new WordArray(words, latin1StrLength);
  }
};
