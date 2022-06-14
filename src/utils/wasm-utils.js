import pako from 'pako';
import index from '../index';

/**
 * Check if WebAssembly is supported or not
 *
 * @return {boolean}
 */
export const wasmSupported = function () {
  return WebAssembly !== 'undefined';
};

/**
 * Decode Base64 encoded .wasm bytes
 *
 * @param compressedBase64Bytes Base64-encoded pako-compressed .wasm bytes
 * @return {Uint8Array|*} .wasm bytes, this is intended to be used by WebAssembly.instantiate
 */
export const generateWasmBytes = function (compressedBase64Bytes) {
  function charCodeAt (c) {
    return c.charCodeAt(0);
  }

  let compressedBytes;
  if (typeof atob === 'function') {
    // Browser case
    compressedBytes = new Uint8Array(atob(compressedBase64Bytes).split('').map(charCodeAt));
  } else {
    compressedBytes = (require('buffer').Buffer).from(compressedBase64Bytes, 'base64');
  }

  return pako.inflate(compressedBytes);
};

/**
 * Load wasm bytes by WebAssembly.instantiate. Note this is async as WebAssembly.instantiate is async.
 * The async WebAssembly.instantiate is recommended instead of its sync variant WebAssembly.instance
 *
 * @param wasmBytes .wasm file bytes
 * @param imports configs for WebAssembly.instantiate, this is related to the generated glue code
 * @return {Promise<WebAssembly.Exports>} the generated WebAssembly target
 */
export const loadWasm = async function(wasmBytes, imports) {
  if (WebAssembly === 'undefined') {
    throw new Error('WebAssembly is not supported.');
  }

  var loadResult = await WebAssembly.instantiate(wasmBytes, imports);
  return loadResult.instance.exports;
};

export const loadAllWasm = async function() {
  await Promise.allSettled(
    Object.values(index.algo).map(algo => {
      if (!algo.loadWasm) {
        return;
      }
      return algo.loadWasm();
    })
  );
};
