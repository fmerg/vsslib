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
const sharing = await shamir(ctx).distribute(secret, 5, 3);
```

```js
const { nrShares, threshold, polynomial } = sharing;
```

```js
const secretShares = await sharing.getSecretShares();
```

```js
const publicShares = await sharing.getPublicShares();
```

## Share verification

### Feldmann VSS scheme

```js
const commitments = await sharing.getFeldmann();
```

```js
const verified = await shamir(ctx).verifyFelmann(secretShare, commitments);
```

### Pedersen VSS scheme

```js
const hPub = await ctx.randomPoint();
```

```js
const { bindings, commitments } = await sharing.getPedersen(hPub);
```

```js
const index = { secretShare };
const binding = bindings[index];
```

```js
const verified = await shamir(ctx).verifyPedersen(secretShare, binding, hPub, commitments);
```

## Reconstruction

```js
const qualifiedShares = secretShares.slice(0, threshold);

const reconstructed = await shamir(ctx).reconstructSecret(qualifiedShares);
```

```js
const qualifiedShares = publicShares.slice(0, threshold);

const reconstructed = await shamir(ctx).reconstructPublic(qualifiedShares);
```
