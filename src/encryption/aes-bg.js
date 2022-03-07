export function aesWasm(wasm) {
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

  let cachegetInt32Memory0 = null;

  function getInt32Memory0() {
    if (cachegetInt32Memory0 === null || cachegetInt32Memory0.buffer !== wasm.memory.buffer) {
      cachegetInt32Memory0 = new Int32Array(wasm.memory.buffer);
    }
    return cachegetInt32Memory0;
  }

  function getArrayU32FromWasm0(ptr, len) {
    return getUint32Memory0().subarray(ptr / 4, ptr / 4 + len);
  }

  /**
   * @param {number} keySize
   * @param {Uint32Array} keyWords
   * @returns {Uint32Array}
   */
  function getKeySchedule(keySize, keyWords) {
    try {
      const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
      var ptr0 = passArray32ToWasm0(keyWords, wasm.__wbindgen_malloc);
      var len0 = WASM_VECTOR_LEN;
      wasm.getKeySchedule(retptr, keySize, ptr0, len0);
      var r0 = getInt32Memory0()[retptr / 4 + 0];
      var r1 = getInt32Memory0()[retptr / 4 + 1];
      var v1 = getArrayU32FromWasm0(r0, r1).slice();
      wasm.__wbindgen_free(r0, r1 * 4);
      return v1;
    } finally {
      wasm.__wbindgen_add_to_stack_pointer(16);
    }
  }

  /**
   * @param {number} keySize
   * @param {Uint32Array} keyWords
   * @returns {Uint32Array}
   */
  function getInvKeySchedule(keySize, keyWords) {
    try {
      const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
      var ptr0 = passArray32ToWasm0(keyWords, wasm.__wbindgen_malloc);
      var len0 = WASM_VECTOR_LEN;
      wasm.getInvKeySchedule(retptr, keySize, ptr0, len0);
      var r0 = getInt32Memory0()[retptr / 4 + 0];
      var r1 = getInt32Memory0()[retptr / 4 + 1];
      var v1 = getArrayU32FromWasm0(r0, r1).slice();
      wasm.__wbindgen_free(r0, r1 * 4);
      return v1;
    } finally {
      wasm.__wbindgen_add_to_stack_pointer(16);
    }
  }

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

  /**
   * @param {string} mode
   * @param {number} nRounds
   * @param {number} nWordsReady
   * @param {number} blockSize
   * @param {Uint32Array} iv
   * @param {Uint32Array} dataWords
   * @param {Uint32Array} keySchedule
   */
  function doEncrypt(mode, nRounds, nWordsReady, blockSize, iv, dataWords, keySchedule) {
    try {
      var ptr0 = passStringToWasm0(mode, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
      var len0 = WASM_VECTOR_LEN;
      var ptr1 = passArray32ToWasm0(iv, wasm.__wbindgen_malloc);
      var len1 = WASM_VECTOR_LEN;
      var ptr2 = passArray32ToWasm0(dataWords, wasm.__wbindgen_malloc);
      var len2 = WASM_VECTOR_LEN;
      var ptr3 = passArray32ToWasm0(keySchedule, wasm.__wbindgen_malloc);
      var len3 = WASM_VECTOR_LEN;
      wasm.doEncrypt(ptr0, len0, nRounds, nWordsReady, blockSize, ptr1, len1, ptr2, len2, ptr3, len3);
    } finally {
      dataWords.set(getUint32Memory0().subarray(ptr2 / 4, ptr2 / 4 + len2));
      wasm.__wbindgen_free(ptr2, len2 * 4);
    }
  }

  /**
   * @param {string} mode
   * @param {number} nRounds
   * @param {number} nWordsReady
   * @param {number} blockSize
   * @param {Uint32Array} iv
   * @param {Uint32Array} dataWords
   * @param {Uint32Array} keySchedule
   * @param {Uint32Array} invKeySchedule
   */
  function doDecrypt(mode, nRounds, nWordsReady, blockSize, iv, dataWords, keySchedule, invKeySchedule) {
    try {
      var ptr0 = passStringToWasm0(mode, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
      var len0 = WASM_VECTOR_LEN;
      var ptr1 = passArray32ToWasm0(iv, wasm.__wbindgen_malloc);
      var len1 = WASM_VECTOR_LEN;
      var ptr2 = passArray32ToWasm0(dataWords, wasm.__wbindgen_malloc);
      var len2 = WASM_VECTOR_LEN;
      var ptr3 = passArray32ToWasm0(keySchedule, wasm.__wbindgen_malloc);
      var len3 = WASM_VECTOR_LEN;
      var ptr4 = passArray32ToWasm0(invKeySchedule, wasm.__wbindgen_malloc);
      var len4 = WASM_VECTOR_LEN;
      wasm.doDecrypt(ptr0, len0, nRounds, nWordsReady, blockSize, ptr1, len1, ptr2, len2, ptr3, len3, ptr4, len4);
    } finally {
      dataWords.set(getUint32Memory0().subarray(ptr2 / 4, ptr2 / 4 + len2));
      wasm.__wbindgen_free(ptr2, len2 * 4);
    }
  }

  return {
    getKeySchedule: getKeySchedule,
    getInvKeySchedule: getInvKeySchedule,
    doEncrypt: doEncrypt,
    doDecrypt: doDecrypt
  };
}


