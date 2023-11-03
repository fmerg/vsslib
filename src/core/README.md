# `vsslib.core`

```js
const core = require('vsslib/core');

const combiner = core.initCombiner('ed25519')
```

## Key reconstruction

```js
const { privateKey, publicKey } = await combiner.reconstructKey(shares);
```

```js
const publicKey = await combiner.reconstructPublic(shares);
```

## Decryptor reconstruction

```js
const [verified, indexes] = await combiner.validatePartialDecryptors(ciphertext, publicShares, shares);
```

```js
const decryptor = await combiner.reconstructDecryptor(shares);
```

## Threshold decryption

```js
const plaintext = await combiner.decrypt(ciphertext, shares);
```
