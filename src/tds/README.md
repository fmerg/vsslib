# `vsslib.tds`

```js
import tds from 'vsslib/tds';

const ctx = backend.initGroup(label);
const combiner = tds(ctx, threshold);
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

### Plain Elgamal Decryption

```js
const { ctx } = publicKey;
const message = (await ctx.randomPoint()).toBytes();

const { ciphertext } = await publicKey.plainEncrypt(message);
```

```js
const plaintext = await combiner.plainDecrypt(ciphertext, partialDecryptors);
```

```js
const plaintext = await combiner.plainDecrypt(ciphertext, partialDecryptors, { skipThreshold: true });
```

### (DH)KEM-Decryption (Key Encapsulation Mechanism)

```js
const message = Uint8Array.from(Buffer.from('destroy earth'));

const { ciphertext, randomness, decryptor } = await publicKey.encrypt(message, {
  scheme: ElgamalSchemes.KEM,
  mode: AesModes.AES_256_CBC,
});
```

```js
const plaintext = await combiner.decrypt(ciphertext, partialDecryptors);
```

```js
const plaintext = await combiner.decrypt(ciphertext, partialDecryptors, { skipThreshold: true });
```

### (DH/EC)IES-Decryption (Integrated Encryption Scheme)

```js
const message = Uint8Array.from(Buffer.from('destroy earth'));

const { ciphertext, randomness, decryptor } = await publicKey.encrypt(message, {
  scheme: ElgamalSchemes.IES,
  mode: AesModes.AES_256_CBC,
  algorithm: Algorithms.SHA256
});
```

```js
const plaintext = await combiner.decrypt(ciphertext, partialDecryptors);
```

```js
const plaintext = await combiner.decrypt(ciphertext, partialDecryptors, { skipThreshold: true });
```
