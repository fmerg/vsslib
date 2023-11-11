# `vsslib.shamir`

```js
const { shamir, backend } = require('vsslib');

const ctx = backend.initGroup('ed25519');
```

```js
const secret = await ctx.randomScalar();
```

## Secret sharing

```js
const n = 5;
const t = 3

const distribution = await shamir.shareSecret(ctx, secret, n, t);
```

```js
const { nrShares, threshold, polynomial } = distribution;
```

```js
const secretShares = await distribution.getSecretShares();
```

```js
const publicShares = await distribution.getPublicShares();
```

## Share verification

### Feldmann VSS scheme

```js
const commitments = await distribution.getFeldmannCommitments();
```

```js
const verified = await shamir.verifySecretShare(ctx, secretShare, commitments);
```

### Pedersen VSS scheme

```js
const hPub = await ctx.randomPoint();
```

```js
const { bindings, commitments } = await distribution.getPedersenCommitments(hPub);
```

```js
const index = { secretShare };
const binding = bindings[index];
```

```js
const verified = await shamir.verifySecretShare(ctx, secretShare, commitments, { binding, hPub });
```

## Reconstruction

```js
const qualifiedShares = secretShares.slice(0, threshold);

const reconstructed = await shamir.reconstructSecret(ctx, qualifiedShares);
```

```js
const qualifiedShares = publicShares.slice(0, threshold);

const reconstructed = await shamir.reconstructPublic(ctx, qualifiedShares);
```
