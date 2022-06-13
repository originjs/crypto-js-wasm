// the file is supposed to be run in node.js
const fs = require('fs');
const pako = require('pako');

const contents = fs.readFileSync('./md5/pkg/md5Rust_bg.wasm', null);
const compressedBytes = pako.deflate(contents);
const base64Encoded = Buffer.from((compressedBytes)).toString('base64');
console.log(base64Encoded);
