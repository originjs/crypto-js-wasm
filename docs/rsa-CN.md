# RSA

RSA is supported in crypto-js-wasm now!

We support all kinds of traditional usage of RSA, including `generation of keys`, `encryption`, `decryption`, `digest`, `sign` and `verify`.

### Configurations

Configurations of RSA should be a object consisting of:

- encryptPadding
  - Type: `string`
  - Default: `OAEP`
  - Valid values: `OAEP`/`PKCS1V15`

Padding mode for `encrypt` and `decrypt`. Case insensitive.

- signPadding
  - Type: `string`
  - Default: `PSS`
  - Valid values: `PSS`/`PKCS1V15`

Padding mode for `sign` and `verify`. Case insensitive.

- hashAlgo
  - Type: `string`
  - Default: `SHA256`
  - Valid values: `MD5`/`SHA1`/`SHA224`/`SHA256`/`SHA384`/`SHA512`/`RIPEMD160`

Hasher for `encrypt`, `decrypt`, `sign` and `verify`. Case insensitive.

- key
  - Type: `string` | `number`
  - Default: `1024`

When `key` is a `string`: path to the RSA key file, or the content of RSA key.

- Content of RSA key: should be a string starting with `-----BEGIN PRIVATE KEY-----` or `-----BEGIN PUBLIC KEY-----`. Supported in `browser` and `nodejs`.
- Path to the RSA key file: strings not starting with `-----BEGIN PRIVATE KEY-----` or `-----BEGIN PUBLIC KEY-----` will be parsed as a file path. Only supported in `nodejs`.

When `key` is a `number`: size of RSA key. We will generate a new pair of RSA public key and private key according to the key size.

- isPublicKey
  - Type: `boolean`
  - Default: `false`

True if the `key` is the public key of RSA. Should be used along with `key`.

Please note that RSA public key can be generated from RSA private key. So if a RSA private key is specified, a corresponding RSA public key will be generated. But RSA private key can **NOT** be generated from RSA public key. 

RSA private key is used in `decrypt` and `sign`. Therefore `decrypt`, `sign`, `generateKeyFile`(when generating `pairs`/`private`) and `getKeyContent`(when getting private key) will throw error if no private key is specified.



Configurations can be updated like this:

```javascript
import C from '@originjs/crypto-js-wasm';

// await the loading wasm
await C.RSA.loadWasm();

const config = {
    encryptPadding: 'OAEP',
    signPadding: 'PSS',
    hashAlgo: 'md5',
    key: '/home/user/rsa_private_key.pem',
    isPublicKey: false
}

// configurations can be passed with updateConfig
C.RSA.updateConfig(config);

// and can be passed along with other apis like encrypt/decrypt/digest/sign/verify
const encryptedMessage = C.RSA.encrypt('message', {
    encryptPadding: 'PKCS1V15'
    key: '/home/user/rsa_private_key.pem',
});

const digest = C.RSA.digest('message', {
    hashAlgo: 'sha256'
});

const signature = C.RSA.sign('message', {
    signPadding: 'pkcs1v15'
});
```

### Create a RSA instance

```javascript
import C from '@originjs/crypto-js-wasm';

// like other algorithms in crypto-js-wasm, you can create a RSA instance
const rsa = new C.algo.RSA();

rsa.loadWasm();
let keyContent = rsa.getKeyContent('private', 'pem');
let encrypted = rsa.encrypt('mesage');

// or you can use the shortcut of RSA
keyContent = C.RSA.getKeyContent('private', 'pem');
encrypted = C.RSA.encrypt('mesage');
```

### Update RSA key

By default, a pair of private key and public key will be generated with size of 1024. You can change the default keys using `updateConfig` or `updateRsaKey`.

```javascript
import C from '@originjs/crypto-js-wasm';

await C.RSA.loadWasm();

// you can get the key content in string
const privateKeyContent = C.RSA.getKeyContent('private', 'pem');
const publicKeyContent = C.RSA.getKeyContent('public', 'pem');

// you can generate another RSA key
C.RSA.updateRsaKey(2048);

// and you can specify an existing RSA key
C.RSA.updateConfig({
    key: '/home/rsa_private_key.pem'
});

// you can generate the RSA key files
// private key file will be generated in ./keys/key.dem
C.RSA.generateKeyFile('private');
// public key : /home/lee/my_rsa_keys/my_rsa_keys_public.pem
// private key : /home/lee/my_rsa_keys/my_rsa_keys_private.pem
C.RSA.generateKeyFile('pairs', 'pem', 'my_rsa_keys', '/home/lee/my_rsa_keys');
```

### Encrypt and decrypt

```javascript
import C from '@originjs/crypto-js-wasm';

await C.RSA.loadWasm();

const msg = 'testMessage';
const encrypted = C.RSA.encrypt(msg, {encryptPadding: 'pkcs1v15',});
const decrypted = C.RSA.decrypt(encrypted, {encryptPadding: 'pkcs1v15',});
expect(new TextDecoder().decode(decrypted)).toBe(msg);
```

### Digest, sign and verify

You can get the digest using hash algorithms like `md5`, `sha1` or other ones by yourself. But it's recommended to use `RSA.digest`, because the hasher you used in `digest` must be the same with the ones in `sign` and `verify`. By using `RSA.digest`, we can assure the consistency of the hasher in `digest`, `sign` and `verify`.

```javascript
import C from '@originjs/crypto-js-wasm';

await C.RSA.loadWasm();

const message = 'test message';
const digest = C.RSA.digest(message, {hashAlgo: 'md5',});
const signature = C.RSA.sign(digest, {signPadding: 'pkcs1v15',});
expect(C.RSA.verify(digest, signature)).toBe(true);

const errorDigest = C.RSA.digest('another message', {hashAlgo: 'md5',});
expect(C.RSA.verify(errorDigest, signature)).toBe(false);
```

