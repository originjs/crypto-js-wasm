# Prepare for compiling

The rust repos require rust toolchains(cargo, rustup, rustc, etc.). You can find the latest rust toolchains [here](https://www.rust-lang.org/tools/install).
Besides the rust toolchains, we also need the [wasm-pack](https://github.com/rustwasm/wasm-pack) to compile our rust code into wasm.

# How to compile

With all gear up, you can compile the rust repos like this(take md5 as an example):
```shell
cd md5
wasm-pack build --release
```
The compiled wasm binary(_bg.wasm) and javascript glue code(_bg.js) will be generated in the `pkg` directory if nothing goes wrong.

# Some extra work

In `crypto-js-wasm`, we use base64-encoded wasm binary(_bg.wasm).
To get a smaller size, we use `pako` to compress the base64-encoded binary.
You can check the `build_rust.js` for more details.
