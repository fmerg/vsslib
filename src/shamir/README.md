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
