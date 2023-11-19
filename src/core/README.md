# `vsslib.core`

```js
const core = require('vsslib/core');

const combiner = core.initCombiner({ label: 'ed25519', threshold: 3 })
```

## Key reconstruction

```js
const { privateKey, publicKey } = await combiner.reconstructKey(privateShares);
```

```js
const { privateKey, publicKey } = await combiner.reconstructKey(privateShares, { skipThreshold: true });
```

```js
const publicKey = await combiner.reconstructPublic(publicShares);
```

```js
const publicKey = await combiner.reconstructPublic(publicShares, { skipThreshold: true });
```

## Decryptor reconstruction

```js
const decryptor = await combiner.reconstructDecryptor(partialDecryptors);
```

```js
const decryptor = await combiner.reconstructDecryptor(partialDecryptors, { skipThreshold: true });
```

### Partial decryptors verification

```js
const { flag, indexes } = await combiner.verifyPartialDecryptors(ciphertext, publicShares, partialDecryptors);
```

```js
await combiner.verifyPartialDecryptors(ciphertext, publicShares, partialDecryptors, { raiseOnInvalid: true });
```

```js
await combiner.verifyPartialDecryptors(ciphertext, publicShares, partialDecryptors, { skipThreshold: true });
```

## Threshold decryption modes

### Plain ElGamal Decryption

```js
const message = await publicKey.ctx.generatePoint();

const { ciphertext } = await publicKey.elgamalEncrypt(message);
```

```js
const plaintext = await combiner.elgamalDecrypt(ciphertext, partialDecryptors);
```

```js
const plaintext = await combiner.elgamalDecrypt(ciphertext, partialDecryptors, { skipThreshold: true });
```

### (DH)KEM-Decryption (Key Encapsulation Mechanism)

```js
const message = Uint8Array.from(Buffer.from('destroy earth'));

const { ciphertext } = await publicKey.kemEncrypt(message);
```

```js
const plaintext = await combiner.kemDecrypt(ciphertext, partialDecryptors);
```

```js
const plaintext = await combiner.kemDecrypt(ciphertext, partialDecryptors, { skipThreshold: true });
```

### (DH/EC)IES-Decryption (Integrated Encryption Scheme)

```js
const message = Uint8Array.from(Buffer.from('destroy earth'));

const { ciphertext } = await publicKey.iesEncrypt(message);
```

```js
const plaintext = await combiner.iesDecrypt(ciphertext, partialDecryptors);
```

```js
const plaintext = await combiner.iesDecrypt(ciphertext, partialDecryptors, { skipThreshold: true });
```
