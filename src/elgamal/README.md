## `vsslib.elgamal`

```js
const elgamal = require('vsslib/elgamal');

const ctx = elgamal.initCrypto('ed25519');
```

```js
const group = ctx.group
```

```js
const modulus = ctx.modulus;      // Field prime order (bigint)
const order = ctx.order;          // Subgroup order (bigint)
const generator = ctx.generator;  // Subgroup generator (Point)
const neutral = ctx.neutral;      // Group neutral element (Point)
```

### Points and scalars

```js
const s = await ctx.randomScalar();
```

```js
const p = await ctx.randomPoint();
```

```js
const p = await ctx.generatePoint(s);
```

```js
const isValid = await ctx.assertValid(p);
```

```js
const areEqual = await ctx.assertEqual(p, q);
```

```js
const pBytes = p.toBytes();
```

```js
const pBack = ctx.unpack(pBytes);
```

```js
const pHex = p.toHex();
```

```js
const pBack = ctx.unhexify(pHex);
```


### Group operations


```js
const u = await ctx.combine(p, q);
```

```js
const v = await ctx.invert(p);
```

```js
const w = await ctx.operate(s, p);
```

### Fiat-Shamir transform

The Fiat-Shamir transform is a hash-based computation used for converting
generic Σ-protocols into non-interactive zero-knowledge (NIZK) proofs.
For example, given scalars `s1, s2, ...` and points `p1, p2, ...`,
the SHA256-based Fiat-Shamir computation is:

```js
const u = await ctx.fiatShamir([s1, s2, ...], [p1, p2, ...], 'sha256');
```

Roughly speaking, this is the point whose discrete logarithm is produced by
hashing together the provided input and the underlying subgroup's parameters.
