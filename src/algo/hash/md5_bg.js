export function md5Wasm(wasm) {
  let cachegetUint32Memory0 = null;

  function getUint32Memory0() {
    if (cachegetUint32Memory0 === null || cachegetUint32Memory0.buffer !== wasm.memory.buffer) {
      cachegetUint32Memory0 = new Uint32Array(wasm.memory.buffer);
    }
    return cachegetUint32Memory0;
  }

  let WASM_VECTOR_LEN = 0;

  function passArray32ToWasm0(arg, malloc) {
    const ptr = malloc(arg.length * 4);
    getUint32Memory0().set(arg, ptr / 4);
    WASM_VECTOR_LEN = arg.length;
    return ptr;
  }

  /**
   * @param {number} doFlush
   * @param {Uint32Array} hashWords
   * @param {Uint32Array} dataWords
   * @param {number} dataSigBytes
   * @param {number} blockSize
   * @param {number} minBufferSize
   * @returns {number}
   */
  function md5Process(doFlush, hashWords, dataWords, dataSigBytes, blockSize, minBufferSize) {
    try {
      var ptr0 = passArray32ToWasm0(hashWords, wasm.__wbindgen_malloc);
      var len0 = WASM_VECTOR_LEN;
      var ptr1 = passArray32ToWasm0(dataWords, wasm.__wbindgen_malloc);
      var len1 = WASM_VECTOR_LEN;
      var ret = wasm.md5Process(doFlush, ptr0, len0, ptr1, len1, dataSigBytes, blockSize, minBufferSize);
      return ret >>> 0;
    } finally {
      hashWords.set(getUint32Memory0().subarray(ptr0 / 4, ptr0 / 4 + len0));
      wasm.__wbindgen_free(ptr0, len0 * 4);
    }
  }

  return {
    md5Process: md5Process
  };
}
