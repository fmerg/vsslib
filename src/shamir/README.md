## `vsslib.shamir`

```js
const elgamal = require('vsslib/elgamal');
const ctx = elgamal.initCrypto('ed25519');
```

```js
const secret = await ctx.randomScalar();
const pub = await ctx.operate(secret, ctx.generator);
```

```js
const shamir = require('vsslib/shamir');
```

### Secret sharing

```js
const { threshold, shares, polynomial, commitments } = await shamir.shareSecret(ctx, secret, 5, 3);
```

#### Share verification

```js
await shamir.verifySecretShare(ctx, share, commitments);
```

#### Secret reconstruction

```
const reconstructed = await shamir.reconstructSecret([1, 2, 3], ctx.order);
```

### Threshold encryption

```js
const message = await ctx.randomPoint();
const { ciphertext } = await ctx.encrypt(message, pub);
```

#### Decryptor shares

```js
const decryptorShare = await shamir.generateDecryptorShare(ctx, ciphertext, share);
```

```js
await shamir.verifyDecryptorShare(ctx, decryptorShare, ciphertext, publicShare);
```


#### Decryptor reconstruction

```js
await shamir.verifyDecryptorShares(ctx, decryptorShares, ciphertext, publicShares);
```

```js
const decryptor = await shamir.reconstructDecryptor(ctx, decryptorShares);
```

#### Decryption

```js
await shamir.verifyDecryptorShares(ctx, decryptorShares, ciphertext, publicShares);
```

```js
const plaintext = await shamir.decrypt(ctx, ciphertext, decryptorShares);
```
