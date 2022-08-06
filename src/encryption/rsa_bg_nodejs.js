import { wasmBytes, } from './rsa_wasm_nodejs';

let webassemblyModule = {
  exports: {},
};
webassemblyModule.require = module.require;
let imports = {};
let wasmImports = {};
imports['__wbindgen_placeholder__'] = wasmImports;
let wasm;
let globalThis;

const heap = new Array(32).fill(undefined);

heap.push(undefined, null, true, false);

function getObject(idx) { return heap[idx]; }

let heap_next = heap.length;

function dropObject(idx) {
  if (idx < 36) return;
  heap[idx] = heap_next;
  heap_next = idx;
}

function takeObject(idx) {
  const ret = getObject(idx);
  dropObject(idx);
  return ret;
}

let cachedTextDecoder;
let cachedTextEncoder;
// only needed in nodejs
if (typeof process !== 'undefined' && process.versions != null && process.versions.node != null) {
  const { TextDecoder, TextEncoder, } = require('util');

  cachedTextDecoder = new TextDecoder('utf-8', { ignoreBOM: true, fatal: true, });
  cachedTextEncoder = new TextEncoder('utf-8');
}

cachedTextDecoder.decode();

let cachedUint8Memory0 = new Uint8Array();

function getUint8Memory0() {
  if (cachedUint8Memory0.byteLength === 0) {
    cachedUint8Memory0 = new Uint8Array(wasm.memory.buffer);
  }
  return cachedUint8Memory0;
}

function getStringFromWasm0(ptr, len) {
  return cachedTextDecoder.decode(getUint8Memory0().subarray(ptr, ptr + len));
}

function addHeapObject(obj) {
  if (heap_next === heap.length) heap.push(heap.length + 1);
  const idx = heap_next;
  heap_next = heap[idx];

  heap[idx] = obj;
  return idx;
}

function debugString(val) {
  // primitive types
  const type = typeof val;
  if (type == 'number' || type == 'boolean' || val == null) {
    return  `${val}`;
  }
  if (type == 'string') {
    return `"${val}"`;
  }
  if (type == 'symbol') {
    const description = val.description;
    if (description == null) {
      return 'Symbol';
    } else {
      return `Symbol(${description})`;
    }
  }
  if (type == 'function') {
    const name = val.name;
    if (typeof name == 'string' && name.length > 0) {
      return `Function(${name})`;
    } else {
      return 'Function';
    }
  }
  // objects
  if (Array.isArray(val)) {
    const length = val.length;
    let debug = '[';
    if (length > 0) {
      debug += debugString(val[0]);
    }
    for(let i = 1; i < length; i++) {
      debug += ', ' + debugString(val[i]);
    }
    debug += ']';
    return debug;
  }
  // Test for built-in
  const builtInMatches = /\[object ([^\]]+)\]/.exec(toString.call(val));
  let className;
  if (builtInMatches.length > 1) {
    className = builtInMatches[1];
  } else {
    // Failed to match the standard '[object ClassName]'
    return toString.call(val);
  }
  if (className == 'Object') {
    // we're a user defined class or Object
    // JSON.stringify avoids problems with cycles, and is generally much
    // easier than looping through ownProperties of `val`.
    try {
      return 'Object(' + JSON.stringify(val) + ')';
    } catch (_) {
      return 'Object';
    }
  }
  // errors
  if (val instanceof Error) {
    return `${val.name}: ${val.message}\n${val.stack}`;
  }
  // TODO we could test for more things here, like `Set`s and `Map`s.
  return className;
}

let WASM_VECTOR_LEN = 0;

const encodeString = (typeof cachedTextEncoder.encodeInto === 'function'
  ? function (arg, view) {
    return cachedTextEncoder.encodeInto(arg, view);
  }
  : function (arg, view) {
    const buf = cachedTextEncoder.encode(arg);
    view.set(buf);
    return {
      read: arg.length,
      written: buf.length,
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

let cachedInt32Memory0 = new Int32Array();

function getInt32Memory0() {
  if (cachedInt32Memory0.byteLength === 0) {
    cachedInt32Memory0 = new Int32Array(wasm.memory.buffer);
  }
  return cachedInt32Memory0;
}

function isLikeNone(x) {
  return x === undefined || x === null;
}

function passArray8ToWasm0(arg, malloc) {
  const ptr = malloc(arg.length * 1);
  getUint8Memory0().set(arg, ptr / 1);
  WASM_VECTOR_LEN = arg.length;
  return ptr;
}

function getArrayU8FromWasm0(ptr, len) {
  return getUint8Memory0().subarray(ptr / 1, ptr / 1 + len);
}

function handleError(f, args) {
  try {
    return f.apply(this, args);
  } catch (e) {
    wasm.__wbindgen_exn_store(addHeapObject(e));
  }
}
/**
 */
export class RsaPrivate {

  static __wrap(ptr) {
    const obj = Object.create(RsaPrivate.prototype);
    obj.ptr = ptr;

    return obj;
  }

  __destroy_into_raw() {
    const ptr = this.ptr;
    this.ptr = 0;

    return ptr;
  }

  free() {
    const ptr = this.__destroy_into_raw();
    wasm.__wbg_rsaprivate_free(ptr);
  }
  /**
   * @param {number | undefined} bits
   * @param {string | undefined} input_key_pem
   */
  constructor(bits, input_key_pem) {
    var ptr0 = isLikeNone(input_key_pem) ? 0 : passStringToWasm0(input_key_pem, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    var len0 = WASM_VECTOR_LEN;
    const ret = wasm.rsaprivate_new(!isLikeNone(bits), isLikeNone(bits) ? 0 : bits, ptr0, len0);
    return RsaPrivate.__wrap(ret);
  }
  /**
   * @param {Uint8Array} ciphertext
   * @param {string} padding_scheme
   * @returns {Uint8Array}
   */
  decrypt(ciphertext, padding_scheme) {
    try {
      const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
      const ptr0 = passArray8ToWasm0(ciphertext, wasm.__wbindgen_malloc);
      const len0 = WASM_VECTOR_LEN;
      const ptr1 = passStringToWasm0(padding_scheme, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
      const len1 = WASM_VECTOR_LEN;
      wasm.rsaprivate_decrypt(retptr, this.ptr, ptr0, len0, ptr1, len1);
      var r0 = getInt32Memory0()[retptr / 4 + 0];
      var r1 = getInt32Memory0()[retptr / 4 + 1];
      var v2 = getArrayU8FromWasm0(r0, r1).slice();
      wasm.__wbindgen_free(r0, r1 * 1);
      return v2;
    } finally {
      wasm.__wbindgen_add_to_stack_pointer(16);
    }
  }
  /**
   * @param {Uint8Array} digest
   * @param {string} padding_str
   * @returns {Uint8Array}
   */
  sign(digest, padding_str) {
    try {
      const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
      const ptr0 = passArray8ToWasm0(digest, wasm.__wbindgen_malloc);
      const len0 = WASM_VECTOR_LEN;
      const ptr1 = passStringToWasm0(padding_str, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
      const len1 = WASM_VECTOR_LEN;
      wasm.rsaprivate_sign(retptr, this.ptr, ptr0, len0, ptr1, len1);
      var r0 = getInt32Memory0()[retptr / 4 + 0];
      var r1 = getInt32Memory0()[retptr / 4 + 1];
      var v2 = getArrayU8FromWasm0(r0, r1).slice();
      wasm.__wbindgen_free(r0, r1 * 1);
      return v2;
    } finally {
      wasm.__wbindgen_add_to_stack_pointer(16);
    }
  }
  /**
   * @param {string} fmt
   * @returns {any}
   */
  getPrivateKeyContent(fmt) {
    const ptr0 = passStringToWasm0(fmt, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.rsaprivate_getPrivateKeyContent(this.ptr, ptr0, len0);
    return takeObject(ret);
  }
  /**
   * @returns {string}
   */
  getPublicKeyPem() {
    try {
      const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
      wasm.rsaprivate_getPublicKeyPem(retptr, this.ptr);
      var r0 = getInt32Memory0()[retptr / 4 + 0];
      var r1 = getInt32Memory0()[retptr / 4 + 1];
      return getStringFromWasm0(r0, r1);
    } finally {
      wasm.__wbindgen_add_to_stack_pointer(16);
      wasm.__wbindgen_free(r0, r1);
    }
  }
}
/**
 */
export class RsaPublic {

  static __wrap(ptr) {
    const obj = Object.create(RsaPublic.prototype);
    obj.ptr = ptr;

    return obj;
  }

  __destroy_into_raw() {
    const ptr = this.ptr;
    this.ptr = 0;

    return ptr;
  }

  free() {
    const ptr = this.__destroy_into_raw();
    wasm.__wbg_rsapublic_free(ptr);
  }
  /**
   * @param {string} input_key_pem
   */
  constructor(input_key_pem) {
    const ptr0 = passStringToWasm0(input_key_pem, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.rsapublic_new(ptr0, len0);
    return RsaPublic.__wrap(ret);
  }
  /**
   * @param {Uint8Array} msg
   * @param {string} padding_scheme
   * @returns {Uint8Array}
   */
  encrypt(msg, padding_scheme) {
    try {
      const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
      const ptr0 = passArray8ToWasm0(msg, wasm.__wbindgen_malloc);
      const len0 = WASM_VECTOR_LEN;
      const ptr1 = passStringToWasm0(padding_scheme, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
      const len1 = WASM_VECTOR_LEN;
      wasm.rsapublic_encrypt(retptr, this.ptr, ptr0, len0, ptr1, len1);
      var r0 = getInt32Memory0()[retptr / 4 + 0];
      var r1 = getInt32Memory0()[retptr / 4 + 1];
      var v2 = getArrayU8FromWasm0(r0, r1).slice();
      wasm.__wbindgen_free(r0, r1 * 1);
      return v2;
    } finally {
      wasm.__wbindgen_add_to_stack_pointer(16);
    }
  }
  /**
   * @param {Uint8Array} digest
   * @param {Uint8Array} sig
   * @param {string} padding_str
   * @returns {boolean}
   */
  verify(digest, sig, padding_str) {
    const ptr0 = passArray8ToWasm0(digest, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(sig, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(padding_str, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ret = wasm.rsapublic_verify(this.ptr, ptr0, len0, ptr1, len1, ptr2, len2);
    return ret !== 0;
  }
  /**
   * @param {string} fmt
   * @returns {any}
   */
  getPublicKeyContent(fmt) {
    const ptr0 = passStringToWasm0(fmt, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.rsapublic_getPublicKeyContent(this.ptr, ptr0, len0);
    return takeObject(ret);
  }
}

wasmImports.__wbindgen_object_drop_ref = function(arg0) {
  takeObject(arg0);
};

wasmImports.__wbindgen_string_new = function(arg0, arg1) {
  const ret = getStringFromWasm0(arg0, arg1);
  return addHeapObject(ret);
};

wasmImports.__wbg_new_693216e109162396 = function() {
  const ret = new Error();
  return addHeapObject(ret);
};

wasmImports.__wbg_stack_0ddaca5d1abfb52f = function(arg0, arg1) {
  const ret = getObject(arg1).stack;
  const ptr0 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
  const len0 = WASM_VECTOR_LEN;
  getInt32Memory0()[arg0 / 4 + 1] = len0;
  getInt32Memory0()[arg0 / 4 + 0] = ptr0;
};

wasmImports.__wbg_error_09919627ac0992f5 = function(arg0, arg1) {
  try {
    console.error(getStringFromWasm0(arg0, arg1));
  } finally {
    wasm.__wbindgen_free(arg0, arg1);
  }
};

wasmImports.__wbindgen_number_new = function(arg0) {
  const ret = arg0;
  return addHeapObject(ret);
};

wasmImports.__wbindgen_object_clone_ref = function(arg0) {
  const ret = getObject(arg0);
  return addHeapObject(ret);
};

wasmImports.__wbindgen_is_undefined = function(arg0) {
  const ret = getObject(arg0) === undefined;
  return ret;
};

wasmImports.__wbindgen_is_object = function(arg0) {
  const val = getObject(arg0);
  const ret = typeof(val) === 'object' && val !== null;
  return ret;
};

wasmImports.__wbg_randomFillSync_91e2b39becca6147 = function() { return handleError(function (arg0, arg1, arg2) {
  getObject(arg0).randomFillSync(getArrayU8FromWasm0(arg1, arg2));
}, arguments); };

wasmImports.__wbg_getRandomValues_b14734aa289bc356 = function() { return handleError(function (arg0, arg1) {
  getObject(arg0).getRandomValues(getObject(arg1));
}, arguments); };

wasmImports.__wbg_process_e56fd54cf6319b6c = function(arg0) {
  const ret = getObject(arg0).process;
  return addHeapObject(ret);
};

wasmImports.__wbg_versions_77e21455908dad33 = function(arg0) {
  const ret = getObject(arg0).versions;
  return addHeapObject(ret);
};

wasmImports.__wbg_node_0dd25d832e4785d5 = function(arg0) {
  const ret = getObject(arg0).node;
  return addHeapObject(ret);
};

wasmImports.__wbindgen_is_string = function(arg0) {
  const ret = typeof(getObject(arg0)) === 'string';
  return ret;
};

wasmImports.__wbg_static_accessor_NODE_MODULE_26b231378c1be7dd = function() {
  const ret = webassemblyModule;
  return addHeapObject(ret);
};

wasmImports.__wbg_require_0db1598d9ccecb30 = function() { return handleError(function (arg0, arg1, arg2) {
  const ret = getObject(arg0).require(getStringFromWasm0(arg1, arg2));
  return addHeapObject(ret);
}, arguments); };

wasmImports.__wbg_crypto_b95d7173266618a9 = function(arg0) {
  const ret = getObject(arg0).crypto;
  return addHeapObject(ret);
};

wasmImports.__wbg_msCrypto_5a86d77a66230f81 = function(arg0) {
  const ret = getObject(arg0).msCrypto;
  return addHeapObject(ret);
};

wasmImports.__wbg_new_ee1a3da85465d621 = function() {
  const ret = new Array();
  return addHeapObject(ret);
};

wasmImports.__wbg_newnoargs_971e9a5abe185139 = function(arg0, arg1) {
  const ret = new Function(getStringFromWasm0(arg0, arg1));
  return addHeapObject(ret);
};

wasmImports.__wbg_call_33d7bcddbbfa394a = function() { return handleError(function (arg0, arg1) {
  const ret = getObject(arg0).call(getObject(arg1));
  return addHeapObject(ret);
}, arguments); };

wasmImports.__wbg_self_fd00a1ef86d1b2ed = function() { return handleError(function () {
  const ret = self.self;
  return addHeapObject(ret);
}, arguments); };

wasmImports.__wbg_window_6f6e346d8bbd61d7 = function() { return handleError(function () {
  const ret = window.window;
  return addHeapObject(ret);
}, arguments); };

wasmImports.__wbg_globalThis_3348936ac49df00a = function() { return handleError(function () {
  const ret = globalThis.globalThis;
  return addHeapObject(ret);
}, arguments); };

wasmImports.__wbg_global_67175caf56f55ca9 = function() { return handleError(function () {
  const ret = global.global;
  return addHeapObject(ret);
}, arguments); };

wasmImports.__wbg_set_64cc39858b2ec3f1 = function(arg0, arg1, arg2) {
  getObject(arg0)[arg1 >>> 0] = takeObject(arg2);
};

wasmImports.__wbg_buffer_34f5ec9f8a838ba0 = function(arg0) {
  const ret = getObject(arg0).buffer;
  return addHeapObject(ret);
};

wasmImports.__wbg_new_cda198d9dbc6d7ea = function(arg0) {
  const ret = new Uint8Array(getObject(arg0));
  return addHeapObject(ret);
};

wasmImports.__wbg_set_1a930cfcda1a8067 = function(arg0, arg1, arg2) {
  getObject(arg0).set(getObject(arg1), arg2 >>> 0);
};

wasmImports.__wbg_length_51f19f73d6d9eff3 = function(arg0) {
  const ret = getObject(arg0).length;
  return ret;
};

wasmImports.__wbg_newwithlength_66e5530e7079ea1b = function(arg0) {
  const ret = new Uint8Array(arg0 >>> 0);
  return addHeapObject(ret);
};

wasmImports.__wbg_subarray_270ff8dd5582c1ac = function(arg0, arg1, arg2) {
  const ret = getObject(arg0).subarray(arg1 >>> 0, arg2 >>> 0);
  return addHeapObject(ret);
};

wasmImports.__wbindgen_debug_string = function(arg0, arg1) {
  const ret = debugString(getObject(arg1));
  const ptr0 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
  const len0 = WASM_VECTOR_LEN;
  getInt32Memory0()[arg0 / 4 + 1] = len0;
  getInt32Memory0()[arg0 / 4 + 0] = ptr0;
};

wasmImports.__wbindgen_throw = function(arg0, arg1) {
  throw new Error(getStringFromWasm0(arg0, arg1));
};

wasmImports.__wbindgen_memory = function() {
  const ret = wasm.memory;
  return addHeapObject(ret);
};

const init = async function () {
  const wasmModule = new WebAssembly.Module(wasmBytes);
  await WebAssembly.instantiate(wasmModule, imports).then((wasmInstance) => {
    wasm = wasmInstance.exports;
    wasmImports.__wasm = wasm;
  });

  cachedInt32Memory0 = new Int32Array(wasm.memory.buffer);
  cachedUint8Memory0 = new Uint8Array(wasm.memory.buffer);
};

export { init, };
