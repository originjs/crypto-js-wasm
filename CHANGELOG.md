## 1.1.1

### Bug fixes:

* Add and fix types for static WordArray.create()(contributed by asivery, [#2](https://github.com/originjs/crypto-js-wasm/pull/2))
* Fix the library for Webpack(contributed by asivery [#3](https://github.com/originjs/crypto-js-wasm/pull/3))
* Use sha256 with iterations of 250000 as default hasher of PBKDF2 to prevent weak security problem. Related to CVE-2023-46233 of crypto-js

### Features:

