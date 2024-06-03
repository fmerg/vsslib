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
const publicShares = await sharing.getPointShares();
```

## Share verification

### Feldmann scheme

```js
// TODO
```

```js
// TODO
```

### Pedersen scheme

```js
const pub = await ctx.randomPoint();
```

```js
// TODO
```

```js
const index = { secretShare };

const binding = bindings[index];
```

```js
// TODO
```

## Reconstruction

```js
const qualifiedShares = secretShares.slice(0, threshold);

const reconstructed = await reconstructSecret(ctx, qualifiedShares);
```

```js
const qualifiedShares = publicShares.slice(0, threshold);

const reconstructed = await reconstructPoint(ctx, qualifiedShares);
```
