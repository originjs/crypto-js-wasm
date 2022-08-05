const path = require('path');
const pkg = require('../package.json');
const babel = require('@rollup/plugin-babel');
const commonjs = require('@rollup/plugin-commonjs');

const banner = `/*
    @license
    crypto-js-wasm v${pkg.version}
    (c) 2022-${new Date().getFullYear()} ${pkg.author.name}
    ${pkg.repository.url}
    Released under the MulanPSL2 License.
*/`;

const uniqResolve = (p) => {
  return path.resolve(__dirname, './', p);
};

module.exports = {
  input: uniqResolve('../src/index.js'),
  output: {
    file: uniqResolve('../lib/index.js'),
    format: 'umd',
    name: 'CryptoJSWasm',
    banner
  },
  plugins: [
    babel.babel({
      exclude: 'node_modules/**',
      plugins: ['@babel/plugin-proposal-class-properties']
    }),
    commonjs(),
  ]
};
