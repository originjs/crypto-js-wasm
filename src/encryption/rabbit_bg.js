export function rabbitWasm(wasm) {
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
  * @param {number} nWordsReady
  * @param {number} blockSize
  * @param {Uint32Array} dataWords
  * @param {Uint32Array} X
  * @param {Uint32Array} C
  * @param {number} b
  * @returns {number}
  */
  function doProcess(nWordsReady, blockSize, dataWords, X, C, b) {
    try {
      var ptr0 = passArray32ToWasm0(dataWords, wasm.__wbindgen_malloc);
      var len0 = WASM_VECTOR_LEN;
      var ptr1 = passArray32ToWasm0(X, wasm.__wbindgen_malloc);
      var len1 = WASM_VECTOR_LEN;
      var ptr2 = passArray32ToWasm0(C, wasm.__wbindgen_malloc);
      var len2 = WASM_VECTOR_LEN;
      var ret = wasm.doProcess(nWordsReady, blockSize, ptr0, len0, ptr1, len1, ptr2, len2, b);
      return ret >>> 0;
    } finally {
      dataWords.set(getUint32Memory0().subarray(ptr0 / 4, ptr0 / 4 + len0));
      wasm.__wbindgen_free(ptr0, len0 * 4);
      X.set(getUint32Memory0().subarray(ptr1 / 4, ptr1 / 4 + len1));
      wasm.__wbindgen_free(ptr1, len1 * 4);
      C.set(getUint32Memory0().subarray(ptr2 / 4, ptr2 / 4 + len2));
      wasm.__wbindgen_free(ptr2, len2 * 4);
    }
  }

  return {
    doProcess: doProcess
  };
}


