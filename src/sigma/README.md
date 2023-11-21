# `vsslib.sigma`

```js
const { sigma, backend } = require('vsslib');

const ctx = backend.initGroup('ed25519');
```

### Fiat-Shamir heuristic

```js
const scalar = await sigma.fiatShamir(ctx, points, scalars, { algorithm, nonce });
```

## Dlog proof (Schnorr protocol)

Generate a SHA256-based NIZK proof-of-knowledge of a secret scalar `x` such
that `v = u ^ x` as follows:

```js
import { dlog } from 'vsslib/sigma';

const proof = await dlog(ctx, 'sha256').prove(x, { u, v });
```

Verify the proof against the `(u, v)` pair as follows:


```js
const verified = await dlog(ctx).verify({ u, v }, proof);
```

## DDH proof (Chaum-Pedersen protocol)

A triple of points `(u, v, w)` is called Decisional Diffie-Hellman (DDH-tuple)
if the discrete logarithm of `w` with respect to the generator (or,
equivalently, any other non-neutral point) is the product of the discrete
logarithms of `u` and `v`; i.e., in multiplicative notation, there exists
scalar scalar `z` such that `u = g ^ x, v = g ^ z, w = g ^ xz`.
Genearate a SHA256-based NIZK proof-of-knowledge of the secret scalar
`z` as follows:

```js
const proof = await ddh(ctx, 'sha256').prove(z, { u, v, w });
```

Verify the proof against the `(u, v, w)` DDH-tuple as follows:

```js
const verified = await ddh(ctx).verify(z, { u, v, w }, proof);
```

Note that `(u, v, w)` being a DDH-tuple as above is equivalent to
`z` being the common discrete logarithm for the pairs `(g, v), (u, w)`,
so that the Chaum-Pedersen protocol is actually a special case of the multiple
AND Dlog protocol.


## Okamoto protocol (proof of Pedersen commitment opening)

Generate a SHA256-based NIZK proof-of-knowledge of secret scalars `s`, `t`
such that `u = g ^ s * h ^ t` as follows:

```js
import { okamoto } from 'vsslib/sigma';

const proof = await okamoto(ctx, 'sha256').prove({ s, t }, { h, u });
```

Verify the proof against the `(h, u)` pair of points as follows:

```js
const verified = await okamoto(ctx).verify({ h, u }, proof);
```

## Dlog equality 

Generate a SHA256-based NIZK proof-of-knowledge of a uniform secret scalar `x` such
that `v_i = u_i ^ x` as follows:

```js
import { eqDlog } from 'vsslib/sigma';

const proof = await eqDlog(ctx, 'sha256').prove(x, [{ u: u_1, v: v_1 }, { u: u_2, v: v_2 }, ...]);
```

Verify the proof against the `(u_i, v_i)` pairs as follows:


```js
const verified = await eqDlog(ctx).verify([{ u: u_1, v: v_1 }, { u: u_2, v: v_2 }, ...], proof);
```

## Dlog conjunction 

Generate a SHA256-based NIZK proof-of-knowledge of secret scalars `x_i` such
that `v_i = u_i ^ x_i` as follows:

```js
import { eqDlog } from 'vsslib/sigma';

const proof = await eqDlog(ctx, algorithm)([x1, x2, ...], [{ u: u_1, v: v_1 }, { u: u_2, v: v_2 }, ...]);
```

Verify the proof against the `(u_i, v_i)` pairs as follows:


```js
const verified = await andDlog(ctx).verify([{ u: u_1, v: v_1 }, { u: u_2, v: v_2 }, ...], proof);
```

## Generic linear relation 

Generate a SHA256-based NIZK proof-of-knowledge of secret scalars `x_j` such
that `v_i = Π_{j} u_ij ^ x_j` as follows:

```js
import { linear } from 'vsslib/sigma';

const proof = await linear(ctx, 'sha256').prove([x1, x2, ...], { us: [[u_11, u_12, ...], [u_21, u_22, ...], ...], vs: [v_1, v_2, ...] });
```

Verify the proof as follows:

```js
const verified = await linear(ctx).verify({ us: [[u_11, u_12, ...], [u_21, u_22, ...], ...], vs: [v_1, v_2, ...] }, proof);
```
