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
Given points `p1, p2, ...` and scalars `s1, s2, ...`, the respective
SHA256-based Fiat-Shamir computation is:

```js
const u = await ctx.fiatShamir([p1, p2, ...], [s1, s2, ...], 'sha256');
```

Roughly speaking, this is the scalar produced by hashing together the provided
input and the underlying subgroup's parameters.


### Dlog proof (Schnorr protocol)

Generate a SHA256-based NIZK proof-of-knowledge of a secret scalar `dlog` being
the discrete logarithm of a point `u` with base point `v` as follows:

```js
const proof = await ctx.proveDlog(dlog, { u, v }, '');
```

Verify the proof against the `(u, v)` pair as follows:


```js
const valid = await ctx.verifyDlog({ u, v }, proof);   // Boolean
```

### Multiple AND Dlog proof

The above primitive is special case of this one. Let

```js
const pairs = [{ u: u1, v: v1 }, { u: u2, v: v2 }, ...];
```

be pairs of points with uniform discrete logarithm, i.e., there exists a secret
scalar `dlog` being the discrete logarithm of `vi` with base `ui` for all `i`.
Generate a SHA256-based NIZK proof-of-knowledge of this secret as follows:

```js
const proof = await ctx.prove_AND_Dlog(dlog, pairs, Algorithms.SHA256);
```

Verify the proof against the pairs `(u1, v1), ...` as follows:

```js
const valid = await ctx.verify_AND_Dlog(pairs, proof);
```
