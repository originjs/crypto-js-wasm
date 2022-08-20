# RSA

crypto-js-wasm当前已经支持RSA!

RSA算法的各种常规用法当前已经支持, 包括`生成密钥`, `加密`, `解密`, `签名`和`验签`.

### 配置说明

RSA的配置项应为一个object, 可以包含如下属性:

- encryptPadding
  - 类型: `string`
  - 默认值: `OAEP`
  - 有效值: `OAEP`/`PKCS1V15`

用于`encrypt`和`decrypt`的填充模式, 大小写不敏感.

- signPadding
  - 类型: `string`
  - 默认值:: `PSS`
  - 有效值: `PSS`/`PKCS1V15`

用于`sign`和`verify`的填充模式, 大小写不敏感.

- hashAlgo
  - 类型: `string`
  - 默认值:: `SHA256`
  - 有效值: `MD5`/`SHA1`/`SHA224`/`SHA256`/`SHA384`/`SHA512`/`RIPEMD160`

用于`encrypt`, `decrypt`, `sign`和`verify`的哈希算法, 大小写不敏感.

- key
  - 类型: `string` | `number`
  - 默认值:: `1024`

当 `key`是`string`类型时: 可以是RSA key文件的路径, 也可以是RSA key的内容.

- RSA key的内容: 应当以 `-----BEGIN PRIVATE KEY-----`或`-----BEGIN PUBLIC KEY-----`开始. 同时在`browser`和`nodejs`环境下可用.
- RSA key文件的路径: 不以`-----BEGIN PRIVATE KEY-----`或`-----BEGIN PUBLIC KEY-----`开始的字符串，将被视作key文件的路径. 只在`nodejs`环境下可用.

当 `key`是`number`类型时: RSA key的位长. 我们会根据这个位长重新生成一对RSA公钥和私钥.

- isPublicKey
  - 类型: `boolean`
  - 默认值:: `false`

若配置的`key`是公钥, 则应设置为true. 需要与`key`同时进行配置。

需要注意的是, RSA私钥可以生成公钥, 因此当配置了RSA私钥时, 对应的RSA公钥也会生成. 但是RSA公钥**不能**生成私钥.

RSA私钥在 `decrypt`和`sign`调用时需要用到, 因此, 如果没有配置RSA私钥, 在调用`decrypt`, `sign`, `generateKeyFile`(生成`pairs`/`private`时) and `getKeyContent`(获取私钥时)时会报错.



配置项可以通过如下方式进行配置:

```javascript
import C from '@originjs/crypto-js-wasm';

// 等待异步的读取wasm完成
await C.RSA.loadWasm();

const config = {
    encryptPadding: 'OAEP',
    signPadding: 'PSS',
    hashAlgo: 'md5',
    key: '/home/user/rsa_private_key.pem',
    isPublicKey: false
}

// 可以通过updateConfig方法更新配置
C.RSA.updateConfig(config);

// 也可以在调用encrypt/decrypt/digest/sign/verify等api时进行配置更新
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

### 创建RSA实例

```javascript
import C from '@originjs/crypto-js-wasm';

// 与crypto-js-wasm中的其他算法一样, 你可以自己创建一个RSA示例
const rsa = new C.algo.RSA();

rsa.loadWasm();
let keyContent = rsa.getKeyContent('private', 'pem');
let encrypted = rsa.encrypt('mesage');

// 你也可以使用我们准备好的RSA示例
keyContent = C.RSA.getKeyContent('private', 'pem');
encrypted = C.RSA.encrypt('mesage');
```

### 更新RSA密钥

默认情况下, 我们会生成一对1024位长的公钥和私钥. 你可以通过`updateConfig`或`updateRsaKey`方法更新密钥.

```javascript
import C from '@originjs/crypto-js-wasm';

await C.RSA.loadWasm();

// 你可以获取默认的RSA密钥
const privateKeyContent = C.RSA.getKeyContent('private', 'pem');
const publicKeyContent = C.RSA.getKeyContent('public', 'pem');

// 你也可以重新生成一份RSA密钥
C.RSA.updateRsaKey(2048);

// 同时也可以指定一个已存在的RSA密钥
C.RSA.updateConfig({
    key: '/home/rsa_private_key.pem'
});

// 你可以生成RSA密钥文件
// 私钥文件会生成在./keys/key.dem
C.RSA.generateKeyFile('private');
// 公钥 : /home/lee/my_rsa_keys/my_rsa_keys_public.pem
// 私钥 : /home/lee/my_rsa_keys/my_rsa_keys_private.pem
C.RSA.generateKeyFile('pairs', 'pem', 'my_rsa_keys', '/home/lee/my_rsa_keys');
```

### 加密和解密

```javascript
import C from '@originjs/crypto-js-wasm';

await C.RSA.loadWasm();

const msg = 'testMessage';
const encrypted = C.RSA.encrypt(msg, {encryptPadding: 'pkcs1v15',});
const decrypted = C.RSA.decrypt(encrypted, {encryptPadding: 'pkcs1v15',});
expect(new TextDecoder().decode(decrypted)).toBe(msg);
```

### 摘要, 签名和验签

你可以用`md5`, `sha1`或其他hash算法自行生成摘要, 但是我们建议你使用`RSA.digest`方法生成密钥, 这是因为你生成密钥所用的hash算法必须与`sign`和`verify`时的一致. 通过使用`RSA.digest`, 我们可以保证`digest`, `sign`和`verify`中hash算法的一致性.

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

