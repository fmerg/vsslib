# `vsslib.shamir`

```js
const { shamir, backend } = require('vsslib');
const ctx = backend.initGroup('ed25519');
const { secret, point: pub } = await ctx.generateKeypair();
```

## Secret sharing

```js
const distribution = await shamir.shareSecret(ctx, secret, 5, 3);
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
const commitments = await distribution.generateCommitments();
```

```js
await shamir.verifySecretShare(ctx, share, commitments);
```

### Pedersen VSS scheme

## Reconstruction

```js
const qualifiedShares = secretShares.slice(0, 3);

const reconstructed = await shamir.reconstructSecret(ctx, qualifiedShares);
```

```js
const qualifiedShares = publicShares.slice(0, 3);

const reconstructed = await shamir.reconstructPublic(ctx, qualifiedShares);
```
