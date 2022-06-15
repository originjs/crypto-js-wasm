import {
  WordArray
} from '../core/core.js';

const parseLoop = (base64Str, base64StrLength, reverseMap) => {
  var words = [];
  var nBytes = 0;
  for (var i = 0; i < base64StrLength; i++) {
    if (i % 4) {
      var bits1 = reverseMap[base64Str.charCodeAt(i - 1)] << ((i % 4) * 2);
      var bits2 = reverseMap[base64Str.charCodeAt(i)] >>> (6 - (i % 4) * 2);
      var bitsCombined = bits1 | bits2;
      words[nBytes >>> 2] |= bitsCombined << (24 - (nBytes % 4) * 8);
      nBytes++;
    }
  }
  return new WordArray(words, nBytes);
};

/**
 * Base64url encoding strategy.
 */
export const Base64url = {
  /**
     * Converts a word array to a Base64url string.
     *
     * @param {WordArray} wordArray The word array.
     *
     * @param {boolean} urlSafe Whether to use url safe
     *
     * @return {string} The Base64url string.
     *
     * @static
     *
     * @example
     *
     *     const base64String = CryptoJSW.enc.Base64url.stringify(wordArray);
     */
  stringify(wordArray, urlSafe) {
    if (urlSafe === undefined) {
      urlSafe = true;
    }
    // Shortcuts
    const words = wordArray.words;
    const sigBytes = wordArray.sigBytes;
    const map = urlSafe ? this._safe_map : this._map;

    // Clamp excess bits
    wordArray.clamp();

    // Convert
    const base64Chars = [];
    for (let i = 0; i < sigBytes; i += 3) {
      const byte1 = (words[i >>> 2]       >>> (24 - (i % 4) * 8))       & 0xff;
      const byte2 = (words[(i + 1) >>> 2] >>> (24 - ((i + 1) % 4) * 8)) & 0xff;
      const byte3 = (words[(i + 2) >>> 2] >>> (24 - ((i + 2) % 4) * 8)) & 0xff;

      const triplet = (byte1 << 16) | (byte2 << 8) | byte3;

      for (let j = 0; (j < 4) && (i + j * 0.75 < sigBytes); j++) {
        base64Chars.push(map.charAt((triplet >>> (6 * (3 - j))) & 0x3f));
      }
    }

    // Add padding
    const paddingChar = map.charAt(64);
    if (paddingChar) {
      while (base64Chars.length % 4) {
        base64Chars.push(paddingChar);
      }
    }

    return base64Chars.join('');
  },

  /**
     * Converts a Base64url string to a word array.
     *
     * @param {string} base64Str The Base64url string.
     *
     * @param {boolean} urlSafe Whether to use url safe
     *
     * @return {WordArray} The word array.
     *
     * @static
     *
     * @example
     *
     *     const wordArray = CryptoJSW.enc.Base64url.parse(base64String);
     */
  parse(base64Str, urlSafe) {
    if (urlSafe === undefined) {
      urlSafe = true;
    }

    // Shortcuts
    let base64StrLength = base64Str.length;
    const map = urlSafe ? this._safe_map : this._map;
    let reverseMap = this._reverseMap;

    if (!reverseMap) {
      reverseMap = this._reverseMap = [];
      for (var j = 0; j < map.length; j++) {
        reverseMap[map.charCodeAt(j)] = j;
      }
    }

    // Ignore padding
    const paddingChar = map.charAt(64);
    if (paddingChar) {
      const paddingIndex = base64Str.indexOf(paddingChar);
      if (paddingIndex !== -1) {
        base64StrLength = paddingIndex;
      }
    }

    // Convert
    return parseLoop(base64Str, base64StrLength, reverseMap);
  },

  _map: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=',
  _safe_map: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'
};
