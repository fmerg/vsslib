# `vsslib.shamir`


```js
const secret = await ctx.randomScalar();
```

## Secret sharing

```js
const sharing = await shareSecret(ctx, 5, 3, secret);
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

### Feldmann scheme

```js
const commitments = await sharing.proveFeldmann();
```

```js
await secretShare.verifyFelmann(commitments);
```

### Pedersen scheme

```js
const pub = await ctx.randomPoint();
```

```js
const { bindings, commitments } = await sharing.provePedersen(pub);
```

```js
const index = { secretShare };

const binding = bindings[index];
```

```js
await secretShare.verifyPedersen(binding, commitments, pub);
```

## Reconstruction

```js
const qualifiedShares = secretShares.slice(0, threshold);

const reconstructed = await reconstructSecret(ctx, qualifiedShares);
```

```js
const qualifiedShares = publicShares.slice(0, threshold);

const reconstructed = await reconstructPublic(ctx, qualifiedShares);
```
