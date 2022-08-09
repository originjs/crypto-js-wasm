const fs = require('fs');
const shell = require('shelljs');
const pako = require('pako');

// create folder
shell.rm('-rf', 'pkg');
shell.mkdir('pkg');

shell.exec('wasm-pack build --target web');

// modify content
const bgOld = fs.readFileSync('./pkg/rsa_rust.js', 'utf8');
const bgTruncated = bgOld.substring(bgOld.indexOf('const heap = new'), bgOld.indexOf('async function load')) +
  bgOld.substring(bgOld.indexOf('function getImports'), bgOld.indexOf('function initMemory'));

const bgSnippet1 = `import { wasmBytes } from './rsa_wasm';
let wasm;
let globalThis;\n`;
const bgSnippet2 = `async function init() {
  const wasmModule = new WebAssembly.Module(wasmBytes);
  await WebAssembly.instantiate(wasmModule, getImports()).then((wasmInstance) => {
    wasm = wasmInstance.exports;
  });

  cachedInt32Memory0 = new Int32Array(wasm.memory.buffer);
  cachedUint8Memory0 = new Uint8Array(wasm.memory.buffer);
}

export { init };`;

const bgFinal = bgSnippet1 + bgTruncated + bgSnippet2;
fs.writeFileSync('./pkg/rsa_bg.js', bgFinal, 'utf8');

// save wasm as base64 to js file
const contents = fs.readFileSync('./pkg/rsa_rust_bg.wasm', null);
const compressedBytes = pako.deflate(contents);
const base64Encoded = Buffer.from((compressedBytes)).toString('base64');
const rsaWasm = `import { generateWasmBytes } from '../utils/wasm-utils';\n
export const wasmBytes = generateWasmBytes('${base64Encoded}');\n`;
fs.writeFileSync('./pkg/rsa_wasm.js', rsaWasm, 'utf8');

shell.rm('-rf', ['pkg/rsa_rust.js', 'pkg/.gitignore', 'pkg/rsa_rust_bg.wasm.d.ts', 'pkg/rsa_rust.d.ts', 'pkg/rsa_rust.js', 'pkg/package.json',]);

console.log('\nBuild complete.');
