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
const distribution = await shamir.shareSecret(ctx, secret, 5, 3);
```

```js
const { threshold, shares, polynomial, commitments } = distribution;
```

```js
const publicShares = await distribution.getPublicShares();
```

#### Share verification

```js
await shamir.verifySecretShare(ctx, share, commitments);
```

#### Secret reconstruction

```js
const qualifiedShares = shares.slice(0, 3);
const reconstructed = await shamir.reconstructSecret(ctx, qualifiedShares);
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
const publicShare = shamir.selectShare(publicShares);
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
