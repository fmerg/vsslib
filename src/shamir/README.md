# `vsslib.shamir`

```js
const { shamir, backend } = require('vsslib');
const ctx = backend.initGroup('ed25519');

const { secret, point: pub } = await ctx.generateKeypair();
```

```js
const secret = await ctx.randomScalar();
```

## Secret sharing

```js
const distribution = await shamir.shareSecret(ctx, secret, 5, 3);
```

```js
const { threshold, secretShares, polynomial, commitments } = distribution;
```

```js
const publicShares = await distribution.publicShares();
```

### Share verification

```js
await shamir.verifySecretShare(ctx, share, commitments);
```

## Secret reconstruction

```js
const qualifiedShares = secretShares.slice(0, 3);

const reconstructed = await shamir.reconstructSecret(ctx, qualifiedShares);
```

## Public reconstruction

```js
const qualifiedShares = publicShares.slice(0, 3);

const reconstructed = await shamir.reconstructPublic(ctx, qualifiedShares);
```


## Threshold decryption

```js
const message = await ctx.randomPoint();

const { ciphertext } = await ctx.encrypt(message, pub);
```

### Partial decryptors

```js
const partialDecryptor = await shamir.generatePartialDecryptor(ctx, ciphertext, share);
```

```js
const publicShare = shamir.selectShare(publicShares);

await shamir.verifyPartialDecryptor(ctx, ciphertext, publicShare, partialDecryptor);
```


### Decryptor reconstruction

```js
await shamir.verifyPartialDecryptors(ctx, ciphertext, publicShares, partialDecryptors);
```

```js
const decryptor = await shamir.reconstructDecryptor(ctx, partialDecryptors);
```

### Decryption

```js
await shamir.verifyPartialDecryptors(ctx, ciphertext, publicShares, partialDecryptors);
```

```js
const plaintext = await shamir.decrypt(ctx, ciphertext, partialDecryptors);
```

```js
const plaintext = await shamir.decrypt(ctx, ciphertext, partialDecryptors, { threshold, publicShares });
```
