export function desWasm(wasm) {
  let WASM_VECTOR_LEN = 0;

  let cachegetUint8Memory0 = null;
  function getUint8Memory0() {
    if (cachegetUint8Memory0 === null || cachegetUint8Memory0.buffer !== wasm.memory.buffer) {
      cachegetUint8Memory0 = new Uint8Array(wasm.memory.buffer);
    }
    return cachegetUint8Memory0;
  }

  const lTextEncoder = typeof TextEncoder === 'undefined' ? (0, module.require)('util').TextEncoder : TextEncoder;

  let cachedTextEncoder = new lTextEncoder('utf-8');

  const encodeString = (typeof cachedTextEncoder.encodeInto === 'function'
    ? function (arg, view) {
      return cachedTextEncoder.encodeInto(arg, view);
    }
    : function (arg, view) {
      const buf = cachedTextEncoder.encode(arg);
      view.set(buf);
      return {
        read: arg.length,
        written: buf.length
      };
    });

  function passStringToWasm0(arg, malloc, realloc) {

    if (realloc === undefined) {
      const buf = cachedTextEncoder.encode(arg);
      const ptr = malloc(buf.length);
      getUint8Memory0().subarray(ptr, ptr + buf.length).set(buf);
      WASM_VECTOR_LEN = buf.length;
      return ptr;
    }

    let len = arg.length;
    let ptr = malloc(len);

    const mem = getUint8Memory0();

    let offset = 0;

    for (; offset < len; offset++) {
      const code = arg.charCodeAt(offset);
      if (code > 0x7F) break;
      mem[ptr + offset] = code;
    }

    if (offset !== len) {
      if (offset !== 0) {
        arg = arg.slice(offset);
      }
      ptr = realloc(ptr, len, len = offset + arg.length * 3);
      const view = getUint8Memory0().subarray(ptr + offset, ptr + len);
      const ret = encodeString(arg, view);

      offset += ret.written;
    }

    WASM_VECTOR_LEN = offset;
    return ptr;
  }

  let cachegetUint32Memory0 = null;
  function getUint32Memory0() {
    if (cachegetUint32Memory0 === null || cachegetUint32Memory0.buffer !== wasm.memory.buffer) {
      cachegetUint32Memory0 = new Uint32Array(wasm.memory.buffer);
    }
    return cachegetUint32Memory0;
  }

  function passArray32ToWasm0(arg, malloc) {
    const ptr = malloc(arg.length * 4);
    getUint32Memory0().set(arg, ptr / 4);
    WASM_VECTOR_LEN = arg.length;
    return ptr;
  }
  /**
   * @param {string} mode
   * @param {number} nWordsReady
   * @param {number} blockSize
   * @param {Uint32Array} iv
   * @param {Uint32Array} dataWords
   * @param {Uint32Array} keyWords
   */
  function doEncrypt(mode, nWordsReady, blockSize, iv, dataWords, keyWords) {
    try {
      var ptr0 = passStringToWasm0(mode, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
      var len0 = WASM_VECTOR_LEN;
      var ptr1 = passArray32ToWasm0(iv, wasm.__wbindgen_malloc);
      var len1 = WASM_VECTOR_LEN;
      var ptr2 = passArray32ToWasm0(dataWords, wasm.__wbindgen_malloc);
      var len2 = WASM_VECTOR_LEN;
      var ptr3 = passArray32ToWasm0(keyWords, wasm.__wbindgen_malloc);
      var len3 = WASM_VECTOR_LEN;
      wasm.doEncrypt(ptr0, len0, nWordsReady, blockSize, ptr1, len1, ptr2, len2, ptr3, len3);
    } finally {
      dataWords.set(getUint32Memory0().subarray(ptr2 / 4, ptr2 / 4 + len2));
      wasm.__wbindgen_free(ptr2, len2 * 4);
    }
  }

  /**
   * @param {string} mode
   * @param {number} nWordsReady
   * @param {number} blockSize
   * @param {Uint32Array} iv
   * @param {Uint32Array} dataWords
   * @param {Uint32Array} keyWords
   */
  function doDecrypt(mode, nWordsReady, blockSize, iv, dataWords, keyWords) {
    try {
      var ptr0 = passStringToWasm0(mode, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
      var len0 = WASM_VECTOR_LEN;
      var ptr1 = passArray32ToWasm0(iv, wasm.__wbindgen_malloc);
      var len1 = WASM_VECTOR_LEN;
      var ptr2 = passArray32ToWasm0(dataWords, wasm.__wbindgen_malloc);
      var len2 = WASM_VECTOR_LEN;
      var ptr3 = passArray32ToWasm0(keyWords, wasm.__wbindgen_malloc);
      var len3 = WASM_VECTOR_LEN;
      wasm.doDecrypt(ptr0, len0, nWordsReady, blockSize, ptr1, len1, ptr2, len2, ptr3, len3);
    } finally {
      dataWords.set(getUint32Memory0().subarray(ptr2 / 4, ptr2 / 4 + len2));
      wasm.__wbindgen_free(ptr2, len2 * 4);
    }
  }

  /**
   * @param {string} mode
   * @param {number} nWordsReady
   * @param {number} blockSize
   * @param {Uint32Array} iv
   * @param {Uint32Array} dataWords
   * @param {Uint32Array} keyWords1
   * @param {Uint32Array} keyWords2
   * @param {Uint32Array} keyWords3
   */
  function tripleEncrypt(mode, nWordsReady, blockSize, iv, dataWords, keyWords1, keyWords2, keyWords3) {
    try {
      var ptr0 = passStringToWasm0(mode, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
      var len0 = WASM_VECTOR_LEN;
      var ptr1 = passArray32ToWasm0(iv, wasm.__wbindgen_malloc);
      var len1 = WASM_VECTOR_LEN;
      var ptr2 = passArray32ToWasm0(dataWords, wasm.__wbindgen_malloc);
      var len2 = WASM_VECTOR_LEN;
      var ptr3 = passArray32ToWasm0(keyWords1, wasm.__wbindgen_malloc);
      var len3 = WASM_VECTOR_LEN;
      var ptr4 = passArray32ToWasm0(keyWords2, wasm.__wbindgen_malloc);
      var len4 = WASM_VECTOR_LEN;
      var ptr5 = passArray32ToWasm0(keyWords3, wasm.__wbindgen_malloc);
      var len5 = WASM_VECTOR_LEN;
      wasm.tripleEncrypt(ptr0, len0, nWordsReady, blockSize, ptr1, len1, ptr2, len2, ptr3, len3, ptr4, len4, ptr5, len5);
    } finally {
      dataWords.set(getUint32Memory0().subarray(ptr2 / 4, ptr2 / 4 + len2));
      wasm.__wbindgen_free(ptr2, len2 * 4);
    }
  }

  /**
   * @param {string} mode
   * @param {number} nWordsReady
   * @param {number} blockSize
   * @param {Uint32Array} iv
   * @param {Uint32Array} dataWords
   * @param {Uint32Array} keyWords1
   * @param {Uint32Array} keyWords2
   * @param {Uint32Array} keyWords3
   */
  function tripleDecrypt(mode, nWordsReady, blockSize, iv, dataWords, keyWords1, keyWords2, keyWords3) {
    try {
      var ptr0 = passStringToWasm0(mode, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
      var len0 = WASM_VECTOR_LEN;
      var ptr1 = passArray32ToWasm0(iv, wasm.__wbindgen_malloc);
      var len1 = WASM_VECTOR_LEN;
      var ptr2 = passArray32ToWasm0(dataWords, wasm.__wbindgen_malloc);
      var len2 = WASM_VECTOR_LEN;
      var ptr3 = passArray32ToWasm0(keyWords1, wasm.__wbindgen_malloc);
      var len3 = WASM_VECTOR_LEN;
      var ptr4 = passArray32ToWasm0(keyWords2, wasm.__wbindgen_malloc);
      var len4 = WASM_VECTOR_LEN;
      var ptr5 = passArray32ToWasm0(keyWords3, wasm.__wbindgen_malloc);
      var len5 = WASM_VECTOR_LEN;
      wasm.tripleDecrypt(ptr0, len0, nWordsReady, blockSize, ptr1, len1, ptr2, len2, ptr3, len3, ptr4, len4, ptr5, len5);
    } finally {
      dataWords.set(getUint32Memory0().subarray(ptr2 / 4, ptr2 / 4 + len2));
      wasm.__wbindgen_free(ptr2, len2 * 4);
    }
  }

  return {
    doEncrypt: doEncrypt,
    doDecrypt: doDecrypt,
    tripleEncrypt: tripleEncrypt,
    tripleDecrypt: tripleDecrypt
  };
}
