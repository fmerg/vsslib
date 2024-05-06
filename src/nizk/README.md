# `vsslib.nizk`

**Non-Interactive Zero-Knowledge (NIZK) proofs**

```js
import { initGroup } from 'vsslib';

const ctx = initGroup('ed25519');
```

```js
import nizk from 'vsslib/nizk';

const sigma = nizk(ctx, Algorithms.SHA256);
```

## Dlog proof (Schnorr protocol)

Prove and verify knowledge of `x` such
that `v = u ^ x` as follows:

```js
const proof = await sigma.proveDlog(x, { u, v });

await sigma.verifyDlog({ u, v }, proof);
```

## DDH proof (Chaum-Pedersen protocol)

Prove and verify knowledge of `z`
such that `u = g ^ x`, `v = g ^ z` and `w = g ^ xz` as follows:


```js
const proof = await sigma.proveDDH(z, { u, v, w });

await sigma.verifyDDH({ u, v, w }, proof);
```

## EQ Dlog proof (Conjunction of Schnorr protocols with uniform logarithm)

Prove and verify knowledge of uniform `x` such that `v_i = u_i ^ x` as follows:

```js
const proof = await sigma.proveEqDlog(x, [
  { u: u_1, v: v_1 },
  { u: u_2, v: v_2 },
  ...
]);

const verified = await sigma.verifyEqDlog([
  { u: u_1, v: v_1 },
  { u: u_2, v: v_2 },
  ...
], proof);
```

## AND Dlog proof (Arbitrary conjunction of Schnorr protocols)

Prove and verify knowledge of `x_i`'s such that `v_i = u_i ^ x_i` as follows:

```js
const proof = await sigma.proveAndDlog([x1, x2, ...], [
  { u: u_1, v: v_1 },
  { u: u_2, v: v_2 },
  ...
]);

await sigma.verifyAndDlog([
  { u: u_1, v: v_1 }, 
  { u: u_2, v: v_2 },
  ...
], proof);
```

## Representation proof (Okamoto protocol)

Prove and verify knowledge of `s`, `t` such that `u = g ^ s * h ^ t` as follows:

```js
const proof = await sigma.proveRepresentation({ s, t }, { h, u });

await sigma.verifyRepresentation({ h, u }, proof);
```

## Generic linear relation proof

Prove and verify knowledge of `x_j`'s such that `v_i = Π_{j} u_ij ^ x_j` as follows:

```js
const proof = await sigma.proveLinearRelation([x1, x2, ...], {
  us: [[u_11, u_12, ...], [u_21, u_22, ...], ...],
  vs: [v_1, v_2, ...]
});

await sigma.verifyLinearRelation({
  us: [[u_11, u_12, ...], [u_21, u_22, ...], ...],
  vs: [v_1, v_2, ...]
}, proof);
```
