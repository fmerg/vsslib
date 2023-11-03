# `vsslib.core`

```js
const core = require('vsslib/core');

const combiner = core.initCombiner({ label: 'ed25519', threshold: 5 })
```

## Key reconstruction

```js
const { privateKey, publicKey } = await combiner.reconstructKey(shares);
```

```js
const { privateKey, publicKey } = await combiner.reconstructKey(shares, { skipThreshold: true });
```

```js
const publicKey = await combiner.reconstructPublic(shares);
```

```js
const publicKey = await combiner.reconstructPublic(shares, { skipThreshold: true });
```

## Partial decryptors validation

```js
const [verified, indexes] = await combiner.validatePartialDecryptors(ciphertext, publicShares, shares);
```

```js
await combiner.validatePartialDecryptors(ciphertext, publicShares, shares, { raiseOnInvalid: true });
```

```js
await combiner.validatePartialDecryptors(ciphertext, publicShares, shares, { skipThreshold: true });
```

## Decryptor reconstruction

```js
const decryptor = await combiner.reconstructDecryptor(shares);
```

```js
const decryptor = await combiner.reconstructDecryptor(shares, { skipThreshold: true });
```

## Threshold decryption

```js
const plaintext = await combiner.decrypt(ciphertext, shares);
```

```js
const plaintext = await combiner.decrypt(ciphertext, shares, { skipThreshold: true });
```
