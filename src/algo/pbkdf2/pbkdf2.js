import {
  Base,
  WordArray
} from '../../core/core.js';
import { SHA256Algo } from '../hash/sha256.js';
import { HMAC } from '../hmac/hmac.js';


/**
 * Password-Based Key Derivation Function 2 algorithm.
 */
export class PBKDF2Algo extends Base {
  /**
   * Initializes a newly created key derivation function.
   *
   * @param {Object} cfg (Optional) The configuration options to use for the derivation.
   *
   * @example
   *
   *     const kdf = new CryptoJSW.algo.PBKDF2();
   *     const kdf = new CryptoJSW.algo.PBKDF2({ keySize: 8 });
   *     const kdf = new CryptoJSW.algo.PBKDF2({ keySize: 8, iterations: 1000 });
   */
  constructor(cfg) {
    super();

    /**
     * Configuration options.
     *
     * @property {number} keySize The key size in words to generate. Default: 4 (128 bits)
     * @property {Hasher} hasher The hasher to use. Default: SHA256
     * @property {number} iterations The number of iterations to perform. Default: 250000
     */
    this.cfg = Object.assign(
      new Base(),
      {
        keySize: 128 / 32,
        hasher: SHA256Algo,
        iterations: 250000
      },
      cfg
    );
  }

  /**
   * SHA256 is the default hasher of pbkdf2.
   * With another hasher configured, user should call the corresponding loadWasm of the configured hasher.
   *
   * @returns {Promise<null>}
   */
  static async loadWasm() {
    return SHA256Algo.loadWasm();
  }

  async loadWasm() {
    return PBKDF2Algo.loadWasm();
  }

  /**
   * Computes the Password-Based Key Derivation Function 2.
   *
   * @param {WordArray|string} password The password.
   * @param {WordArray|string} salt A salt.
   *
   * @return {WordArray} The derived key.
   *
   * @example
   *
   *     const key = kdf.compute(password, salt);
   */
  compute(password, salt) {
    // Shortcut
    const { cfg } = this;

    // Init HMAC
    const hmac = new HMAC(cfg.hasher, password);

    // Initial values
    const derivedKey = new WordArray();
    const blockIndex = new WordArray([0x00000001]);

    // Shortcuts
    const derivedKeyWords = derivedKey.words;
    const blockIndexWords = blockIndex.words;
    const { keySize, iterations } = cfg;

    // Generate key
    while (derivedKeyWords.length < keySize) {
      const block = hmac.update(salt).finalize(blockIndex);
      hmac.reset();

      // Shortcuts
      const blockWords = block.words;
      const blockWordsLength = blockWords.length;

      // Iterations
      let intermediate = block;
      for (let i = 1; i < iterations; i++) {
        intermediate = hmac.finalize(intermediate);
        hmac.reset();

        // Shortcut
        const intermediateWords = intermediate.words;

        // XOR intermediate with block
        for (let j = 0; j < blockWordsLength; j++) {
          blockWords[j] ^= intermediateWords[j];
        }
      }

      derivedKey.concat(block);
      blockIndexWords[0]++;
    }
    derivedKey.sigBytes = keySize * 4;

    return derivedKey;
  }
}

/**
 * Computes the Password-Based Key Derivation Function 2.
 *
 * @param {WordArray|string} password The password.
 * @param {WordArray|string} salt A salt.
 * @param {Object} cfg (Optional) The configuration options to use for this computation.
 *
 * @return {WordArray} The derived key.
 *
 * @static
 *
 * @example
 *
 *     const key = CryptoJSW.PBKDF2(password, salt);
 *     const key = CryptoJSW.PBKDF2(password, salt, { keySize: 8 });
 *     const key = CryptoJSW.PBKDF2(password, salt, { keySize: 8, iterations: 1000 });
 */
export const PBKDF2 = (password, salt, cfg) =>new PBKDF2Algo(cfg).compute(password, salt);
