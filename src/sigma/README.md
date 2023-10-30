# `vsslib.sigma`

```js
const { sigma, backend } = require('vsslib');

const ctx = backend.initGroup('ed25519');
```

## Dlog proof (Schnorr protocol)

Generate a SHA256-based NIZK proof-of-knowledge of a secret scalar `z` being
the discrete logarithm of a point `u` with base point `v` as follows:

```js
const proof = await sigma.proveDlog(ctx, z, u, v, { algorithm: 'sha256' });
```

Verify the proof against the `(u, v)` pair as follows:


```js
const valid = await sigma.verifyDlog(ctx, u, v, proof);   // boolean
```

## Multiple AND Dlog proof

The above primitive is special case of this one. Let

```js
(u1, v1), (u2, v2), ...
```

be pairs of points with uniform discrete logarithm, i.e., there exists a secret
scalar `z` being the discrete logarithm of `vi` with base `ui` for all `i`.
Generate a SHA256-based NIZK proof-of-knowledge of this secret as follows:

```js
const proof = await sigma.proveEqDlog(ctx, z, [{ u: u1, v: v1 }, { u: u2, v: v2 }, ...], { algorithm: 'sha256' });
```

Verify the proof against the acclaimed pairs as follows:

```js
const valid = await sigma.verifyEqDlog(ctx, [{ u: u1, v: v1 }, { u: u2, v: v2 }, ...], proof);
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
const proof = await sigma.proveDDH(ctx, z, { u, v, w }, { algorithm: 'sha256' });
```

Verify the proof against the `(u, v, w)` DDH-tuple as follows:

```js
const valid = await sigma.verifyDDH(ctx, { u, v, w }, proof);
```

Note that `(u, v, w)` being a DDH-tuple as above is equivalent to
`z` being the common discrete logarithm for the pairs `(g, v), (u, w)`,
so that the Chaum-Pedersen protocol is actually a special case of the multiple
AND Dlog protocol.
