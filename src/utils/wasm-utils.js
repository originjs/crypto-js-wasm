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
 * @param base64Bytes Base64 encoded .wasm bytes
 * @return {Uint8Array|*} .wasm bytes, this is intended to be used by WebAssembly.instantiate
 */
export const generateWasmBytes = function (base64Bytes) {
  function charCodeAt (c) {
    return c.charCodeAt(0);
  }

  if (typeof atob === 'function') {
    // Browser case
    return new Uint8Array(atob(base64Bytes).split('').map(charCodeAt));
  }

  // NodeJS case
  return (require('buffer').Buffer).from(base64Bytes, 'base64');
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
