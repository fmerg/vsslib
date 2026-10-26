# Usage

For the API reference, run `npm run docs`; for complete flows, see
[`examples`](./examples/dkg.ts); for performance, see
[PERFORMANCE.md](./PERFORMANCE.md).

Vsslib validates every input and hardens its own arithmetic on secrets; the
safeguards that depend on the application are up to the caller, e.g. nonces
against replay, zeroization of returned secrets, complaint handling in a DKG
and isolation in browsers (see [SECURITY.md](./SECURITY.md)).

## Cryptosystem setup

Vsslib works over any discrete-log group, which a backend provides; parties
interact only if they use the same backend.

```js
import { initBackend } from "vsslib";

const ctx = initBackend("ed25519");
```

The built-in backends wrap
[`noble-curves`](https://github.com/paulmillr/noble-curves). The Edwards curves
`ed25519` and `ed448` (cofactors 8 and 4) encode points per RFC 8032 in 32 and
57 bytes, and `jubjub` (cofactor 8) per Zcash in 32 bytes; on these, vsslib
rejects points outside the prime-order subgroup. The prime-order groups
`ristretto255` and `decaf448` encode points per RFC 9496 in 32 and 56 bytes. The
prime-order Weierstrass curves `secp256k1`, `p256`, `p384` and `p521` (NIST
P-256, P-384 and P-521) accept only compressed SEC1 points, in 33, 33, 49 and
67 bytes, with the single byte `0x00` for the point at infinity.

Scalars are fixed-width little-endian on every backend: 32 bytes, except 56 on
`ed448` and `decaf448`, 48 on `p384` and 66 on `p521`. Reverse the bytes of SEC1
secret keys when exchanging them with other libraries. Pedersen bases are
derived by RFC 9380 hash-to-curve (the Zcash group hash on `jubjub`).

Any other implementation of the `Group` interface can replace a built-in
backend (see [Backend](./README.md#backend)).

### Secrets and public keys

A party generates a keypair, or derives the public key of a secret:

```js
import { randomSecret, extractPublic } from "vsslib";

const { secret, publicBytes } = await randomSecret(ctx);
const same = await extractPublic(ctx, secret);
```

`secret` is a uniformly random scalar and `publicBytes` the generator raised to
it. Functions taking secrets or public keys throw `InvalidInput` on invalid
values and non-canonical encodings (see
[Input validation](./SECURITY.md#input-validation)).

Related helpers: `randomPublic`, `isEqualSecret`, `isEqualPublic`, `isKeypair`,
`addSecrets` and `combinePublics`.

## Shamir's Secret Sharing (SSS)

### Sharing a secret

The dealer shares a fresh secret, or a given one:

```js
import { shareSecret } from "vsslib";

const { secret, sharing } = await shareSecret(ctx, n, t);
const { sharing: other } = await shareSecret(ctx, n, t, secret);
```

`shareSecret` creates `n` shares, any `t` of which recover the secret. It throws
`ShamirError` unless `1 <= t <= n < q`, with `q` the group order, and
`InvalidInput` on an invalid secret.

Up to `t - 1` shares, at indexes 1 to `t - 1`, may be fixed in advance:

```js
const { sharing } = await shareSecret(ctx, n, t, secret, [
  { index: 1, value: value1 },
  { index: 2, value: value2 },
]);
```

This throws `ShamirError` on `t` or more predefined shares, on out-of-range or
repeated indexes, on invalid values, and if the predefined shares would let
fewer than `t` shares recover the secret (see [Threshold](#threshold)).

### Accessing the shares

The dealer reads the secret and the shares to distribute from the sharing:

```js
const secret = sharing.getOriginalSecret();
const secretShares = await sharing.getSecretShares();   // [{ value, index }, ...]
const publicShares = await sharing.getPublicShares();
const { secretShare, publicShare } = await sharing.getShare(i);
```

A public share is the generator raised to the secret share, i.e.
`extractPublic(ctx, secretShare.value)` at the same index. The sharing holds the
secret, so drop it once the shares are distributed (see
[Memory](./SECURITY.md#memory)).

### Combining shares

A combiner recovers the secret from `t` secret shares, or the public key from
`t` public shares:

```js
import { combineSecretShares, combinePublicShares } from "vsslib";

const combinedSecret = await combineSecretShares(ctx, secretShares, t);
const combinedPublic = await combinePublicShares(ctx, publicShares, t);
```

Both interpolate at zero, over scalars and in the exponent respectively, and
throw `InvalidInput` on fewer than `t` shares or invalid indexes. Neither
verifies the shares; use [VSS](#verifiable-secret-sharing-vss) or
[verifiable public key recovery](#verifiable-public-key-recovery) for that.

Protocols combining shares themselves can compute the Lagrange coefficients at
zero, as bigints modulo the group order:

```js
import { computeLambda, computeLambdas } from "vsslib";

const lambdas = computeLambdas(ctx, [1, 3, 4]);   // one per index, in order
const lambda = computeLambda(ctx, 3, [1, 3, 4]);  // that of index 3 only
```

`computeLambdas` inverts once for all coefficients, so prefer it when all are
needed (see [Common denominator](./PERFORMANCE.md#common-denominator)). Both
throw `InvalidInput` unless the indexes are distinct positive safe integers
below the group order; `computeLambda` also if `index` is not among them.

## Verifiable Secret Sharing (VSS)

To defend against a malicious dealer, shareholders check that their shares stem
from one sharing. In the Feldman and Pedersen schemes, the dealer broadcasts
commitments to the sharing polynomial and sends each shareholder a packet,
verified against them. Verification requires exactly `t` commitments, which
bound the degree of the sharing polynomial by `t - 1` (see
[Threshold](#threshold)).

> **Warning**
> Applying VSS correctly in a DKG protocol is out of scope: handling
> verification errors per the protocol's complaint policy, and ensuring that
> only honest parties end up with a share, is up to the caller.

### Feldman scheme

```js
import { createFeldmanPackets, parseFeldmanPacket, InvalidSecretShare } from "vsslib";

// Dealer: broadcast the commitments, send each packet privately
const { packets, commitments } = await createFeldmanPackets(sharing);

// Shareholder
try {
  const { share } = await parseFeldmanPacket(ctx, commitments, packet, t);
} catch (err) {
  if (err instanceof InvalidSecretShare) {
    // complain against the dealer, as the protocol prescribes
  }
}
```

`parseFeldmanPacket` throws `InvalidSecretShare` if the share does not match the
commitments or these do not number `t`, and `InvalidInput` on malformed input.
`verifyFeldmanCommitments(ctx, commitments, share, t)` checks a share received
otherwise, with the same errors. The first Feldman commitment is the public key
of the secret, which every recipient thus learns.

### Pedersen scheme

Pedersen commitments hide the secret, at the cost of a second base `h`
whose discrete log nobody may know. All parties derive it from a public seed
they agree on, e.g. a session identifier:

```js
import { derivePedersenBase } from "vsslib";

const pedersenBase = await derivePedersenBase(ctx, seed);  // seed is optional
```

> **Warning**
> Never use a base generated by a party, e.g. with `randomPublic` (see
> [Pedersen base](#pedersen-base)).

Reuse the base: vsslib keeps it parsed and, from its second use on, attaches a
precomputed table (see
[Pedersen base table](./PERFORMANCE.md#pedersen-base-table)).

```js
import { createPedersenPackets, parsePedersenPacket } from "vsslib";

// Dealer: broadcast the commitments, send each packet privately
const { packets, commitments } = await createPedersenPackets(sharing, pedersenBase);

// Shareholder
const { share, binding } = await parsePedersenPacket(ctx, commitments, pedersenBase, packet, t);
```

Each packet carries the share's secret `binding`, needed only for verification.
Errors are as for Feldman;
`verifyPedersenCommitments(ctx, commitments, pedersenBase, share, binding, t)`
verifies a share received otherwise.

## Verifiable public key recovery

To reconstruct the public key of a shared secret, e.g. for certification, a
combiner collects public shares, each with a Schnorr proof of knowledge of the
secret share.

```js
import { createSchnorrPacket, recoverPublic } from "vsslib";

// Shareholder
const packet = await createSchnorrPacket(ctx, share, { algorithm: "sha256", nonce });

// Combiner
const { recovered } = await recoverPublic(ctx, packets, t, { algorithm: "sha256", nonces });
```

The hash algorithm defaults to SHA-256 and must match on both sides, else the
proofs fail. The optional nonce defends against replayed proofs (see
[Replay attacks](./SECURITY.md#replay-attacks)): the combiner sends each
shareholder a fresh nonce, e.g. from `randomNonce()`, and passes them to
`recoverPublic` by index.
`parseSchnorrPacket(ctx, packet, { algorithm, nonce })` verifies a single
packet.

`recoverPublic` throws `InvalidPublicShare` at the first failing proof, and
`InvalidInput` on fewer than `t` packets, on indexes that are not distinct
positive integers and at the first malformed packet.

It interpolates over all packets whose proofs verify, not just `t`, which
agrees with any `t` of them as long as the shares lie on one polynomial of
degree `t - 1`. A validly proven share off that polynomial distorts the result,
and only the dealer's commitments reveal it (see
[VSS](#verifiable-secret-sharing-vss)).

> **Warning**
> Recovery checks only that each shareholder knows its secret share, not that
> the public shares stem from a Shamir sharing. `combinePublicShares` checks
> neither.

To identify every cheating shareholder instead of aborting at the first:

```js
const { recovered, blame } = await recoverPublic(ctx, packets, t, { errorOnInvalid: false });
if (blame.length > 0) {
  // hold the shareholders of these public shares accountable
}
```

`blame` lists the public shares, with their indexes, whose proofs fail or whose
packets are malformed; the result is interpolated over the rest. If fewer than
`t` remain, it throws `InvalidPublicShare`; invalid or duplicate indexes still
throw `InvalidInput`, since they cannot be attributed to one shareholder.
Always check `blame` with this option.

### Sharing integrity

#### Threshold

A sharing of threshold `t` uses a polynomial of degree `t - 1`, so that any `t`
(but not less) shares recover the secret key. A dealer may announce `t` but
share a polynomial of another degree `d`:

- `d > t - 1`: `t` shares do not recover the secret.
- `d < t - 1`: `d + 1` shares, fewer than `t`, recover it.

Verification requires exactly `t` commitments, which bound the degree by
`t - 1`, and throws `InvalidSecretShare` otherwise; this rules out the first
case. The second remains possible with vanished top coefficients, which
verification accepts: dealing commits to them with the neutral element, and
Pedersen commitments hide them. A dishonest dealer, who knows the secret anyway,
can thus still cause it.

Predefined shares can cause it without dishonesty. With `t - 1` predefined
shares, no point of the sharing polynomial is random; if they lie with the
secret on a polynomial of lower degree (e.g. all equal to the secret), the
sharing has that degree. `shareSecret` detects this and throws `ShamirError`.

#### Pedersen base

Pedersen commitments bind the dealer only if nobody knows the discrete log of
the base `h`; whoever knows it can distribute invalid shares that pass
verification. `derivePedersenBase` hashes a public seed to the group, which
yields an element of unknown discrete log; parsing rejects the neutral element
and the generator (discrete logs 0 and 1).
