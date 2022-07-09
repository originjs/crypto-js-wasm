const fs = require('fs');
const shell = require('shelljs');

// create folder
shell.rm('-rf', 'pkgs');
shell.mkdir('pkgs');

// generate nodejs pkg
shell.exec('wasm-pack build --target nodejs');

const nodeOld = fs.readFileSync('./pkg/rsa_rust.js', 'utf8');
const nodeTruncated = nodeOld.substring(0, nodeOld.indexOf('const path = require(\'path\')'));
const nodeFinal = nodeTruncated + `
module.exports.init = async function () {
    const path = require('path').join(__dirname, 'rsa_rust_bg.wasm');
    const bytes = require('fs').readFileSync(path);

    const wasmModule = new WebAssembly.Module(bytes);
    await WebAssembly.instantiate(wasmModule, imports).then((wasmInstance) => {
        wasm = wasmInstance.exports;
        module.exports.__wasm = wasm;
    })

    cachedInt32Memory0 = new Int32Array(wasm.memory.buffer);
    cachedUint8Memory0 = new Uint8Array(wasm.memory.buffer);
}
`;

fs.writeFileSync('./pkg/rsa_rust.js', nodeFinal, 'utf8');

shell.rm('-rf', ['pkg/.gitignore', 'pkg/rsa_rust_bg.wasm.d.ts', 'pkg/rsa_rust.d.ts']);
shell.mv('pkg', 'pkgs/nodejs');

// generate browser pkg
shell.exec('wasm-pack build --target web');

const webOld = fs.readFileSync('./pkg/rsa_rust.js', 'utf8');
const webFinal = webOld.replace('default init', '{ init }');

fs.writeFileSync('./pkg/rsa_rust.js', webFinal, 'utf8');

shell.rm('-rf', ['pkg/.gitignore', 'pkg/rsa_rust_bg.wasm.d.ts', 'pkg/rsa_rust.d.ts']);
shell.mv('pkg', 'pkgs/browser');

// generate other files using template
shell.cp('-r', 'pkgs_template/*', 'pkgs');

console.log('\nSuccessfully generated pkgs! Now you can run \'npm run dev:node\' or \'npm run dev:browser\'');
