# Usage

This guide walks through the operations of vsslib with short examples. For the
signatures and every thrown error, see the API reference (`npm run docs`); for
complete flows, see [`examples`](./examples/dkg.ts). Security considerations
are in [SECURITY.md](./SECURITY.md) and measurements in
[PERFORMANCE.md](./PERFORMANCE.md).

## Cryptosystem setup

Every operation takes a backend instance, `ctx`, which the parties of a
protocol must share:

```js
import { initBackend } from "vsslib";

const ctx = initBackend("ed25519");
```

The built-in backends are the following.

| System         | Group                      | Point encoding     | Point bytes | Scalar bytes |
|----------------|----------------------------|--------------------|-------------|--------------|
| `ed25519`      | edwards25519, cofactor 8   | RFC 8032           | 32          | 32           |
| `ed448`        | edwards448, cofactor 4     | RFC 8032           | 57          | 56           |
| `jubjub`       | Jubjub, cofactor 8         | Zcash              | 32          | 32           |
| `ristretto255` | ristretto255, prime order  | RFC 9496           | 32          | 32           |
| `decaf448`     | decaf448, prime order      | RFC 9496           | 56          | 56           |
| `secp256k1`    | secp256k1, prime order     | SEC1, compressed   | 33          | 32           |
| `p256`         | NIST P-256, prime order    | SEC1, compressed   | 33          | 32           |
| `p384`         | NIST P-384, prime order    | SEC1, compressed   | 49          | 48           |
| `p521`         | NIST P-521, prime order    | SEC1, compressed   | 67          | 66           |

- On the curves with a cofactor, points outside the prime-order subgroup are
  rejected.
- SEC1 points are accepted only compressed, with the single byte `0x00` for the
  point at infinity; uncompressed and hybrid encodings are rejected.
- Scalars are encoded little-endian with fixed width on every backend, so the
  conventionally big-endian secret keys of the SEC1 curves must be byte-reversed
  when exchanged with other libraries.
- Pedersen bases are derived with RFC 9380 hash-to-curve, except on `jubjub`,
  which uses the Zcash group hash.

Any other implementation of the `Group` interface can be passed in place of a
built-in backend (see [Backend](./README.md#backend-overview)).

## Secrets and public keys

```js
import { randomSecret, extractPublic } from "vsslib";

const { secret, publicBytes } = await randomSecret(ctx);
const same = await extractPublic(ctx, secret);
```

`secret` encodes a uniformly random scalar modulo the group order, and
`publicBytes` the generator raised to it. Every function taking a secret or a
public key throws `InvalidInput` on bytes that are not a canonical encoding;
see [Input validation](./SECURITY.md#input-validation). The related helpers are
`randomPublic`, `isEqualSecret`, `isEqualPublic`, `isKeypair`, `addSecrets` and
`combinePublics`.

## <a name="shamir-secret-sharing"></a>Shamir's Secret Sharing (SSS)

### Sharing a secret

```js
import { shareSecret } from "vsslib";

const { secret, sharing } = await shareSecret(ctx, n, t);          // fresh secret
const { sharing: other } = await shareSecret(ctx, n, t, secret);   // given secret
```

This creates an `(n, t)`-sharing, i.e. `n` shares of which any `t` recover the
secret. It throws `ShamirError` unless `1 <= t <= n < q`, with `q` the group
order, and `InvalidInput` on an invalid secret.

Up to `t - 1` shares may be fixed in advance, at indexes from 1 to `t - 1`:

```js
const { sharing } = await shareSecret(ctx, n, t, secret, [
  { index: 1, value: value1 },
  { index: 2, value: value2 },
]);
```

This throws `ShamirError` if there are `t` or more predefined shares, if an
index is out of range or repeated, or if a value is invalid. It also throws if
`t - 1` predefined shares lie with the secret on a polynomial of degree below
`t - 1`, e.g. if they all equal the secret, since fewer than `t` shares would
then recover it.

### Accessing the shares

```js
const secret = sharing.getOriginalSecret();
const secretShares = await sharing.getSecretShares();   // [{ value, index }, ...]
const publicShares = await sharing.getPublicShares();
const { secretShare, publicShare } = await sharing.getShare(i);
```

A public share is the generator raised to the secret share, i.e.
`await extractPublic(ctx, secretShare.value)` with the same index. Drop the
sharing once the shares are distributed, since it holds the secret (see
[Side-channel attacks](./SECURITY.md#side-channel-attacks)).

### <a name="combination-of-shares"></a>Combining shares

```js
import { combineSecretShares, combinePublicShares } from "vsslib";

const combinedSecret = await combineSecretShares(ctx, secretShares, t);
const combinedPublic = await combinePublicShares(ctx, publicShares, t);
```

Both interpolate at zero, over scalars and in the exponent respectively, and
throw `InvalidInput` on fewer than `t` shares or on invalid indexes. Neither
verifies the shares; use the [VSS schemes](#verifiable-secret-sharing) or
[verifiable public recovery](#verifiable-public-recovery) for that.

Protocols that combine shares themselves can compute the Lagrange coefficients
at zero, as bigints modulo the group order:

```js
import { computeLambda, computeLambdas } from "vsslib";

const lambdas = computeLambdas(ctx, [1, 3, 4]);   // one per index, in order
const lambda = computeLambda(ctx, 3, [1, 3, 4]);  // that of index 3 only
```

Prefer `computeLambdas` when all coefficients are needed, since it inverts once
for all of them (see [Common denominator](./PERFORMANCE.md#common-denominator)).
Both throw `InvalidInput` unless the indexes are distinct positive safe integers
below the group order, and `computeLambda` also if `index` is not among them.

## <a name="verifiable-secret-sharing"></a>Verifiable Secret Sharing (VSS)

Shareholders must be able to check that their shares come from one and the same
sharing, so as to defend against a malicious dealer. In the Feldman and Pedersen
schemes, the dealer broadcasts commitments to the sharing polynomial and sends
each shareholder a packet, which the shareholder verifies against them.
Commitments always number `t`, and verification rejects any other number, so
that a dealer cannot share with another threshold than the agreed one.

> **Warning**
> Applying VSS correctly in a DKG protocol is out of the library's scope. It is
> the caller's responsibility to handle verification errors according to the
> protocol's complaint policy, and to ensure that only honest parties end up
> with a share.

### <a name="feldman-scheme"></a>Feldman scheme

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
commitments or if these do not number `t`, and `InvalidInput` on malformed
input. A share received otherwise is checked by
`verifyFeldmanCommitments(ctx, commitments, share, t)`, which throws the same
errors. Feldman commitments reveal the public key of the secret.

### <a name="pedersen-scheme"></a>Pedersen scheme

Pedersen commitments hide the secret as well, at the cost of a second base `h`
whose discrete log with respect to the generator must be unknown to everyone.
Derive it from a public seed agreed upon by the parties, e.g. a session
identifier:

```js
import { derivePedersenBase } from "vsslib";

const pedersenBase = await derivePedersenBase(ctx, seed);  // seed is optional
```

> **Warning**
> Never use a base generated by one of the parties, e.g. with `randomPublic`.
> Whoever knows its discrete log can open commitments to arbitrary values,
> i.e. distribute invalid shares that pass verification.

Reuse the same base across operations: vsslib keeps the parsed base and, from
its second use on, a precomputed table for it (see
[Pedersen base table](./PERFORMANCE.md#pedersen-base-table)).

```js
import { createPedersenPackets, parsePedersenPacket } from "vsslib";

const { packets, commitments } = await createPedersenPackets(sharing, pedersenBase);
const { share, binding } = await parsePedersenPacket(ctx, commitments, pedersenBase, packet, t);
```

Each packet carries the share's secret `binding`, which verification uses and
which may be discarded afterwards. Errors are as in the Feldman scheme, and
`verifyPedersenCommitments(ctx, commitments, pedersenBase, share, binding, t)`
verifies a share received otherwise.

## <a name="verifiable-public-recovery"></a>Verifiable public recovery

To reconstruct the public key of a shared secret, e.g. for certification, a
combiner collects public shares from the shareholders, each with a Schnorr proof
of knowledge of the secret share.

```js
import { createSchnorrPacket, recoverPublic } from "vsslib";

// Shareholder
const packet = await createSchnorrPacket(ctx, share, { algorithm: "sha256", nonce });

// Combiner
const { recovered } = await recoverPublic(ctx, packets, t, { algorithm: "sha256", nonces });
```

The hash algorithm defaults to SHA-256 and must be the same on both sides; a
mismatch makes the proofs fail. The nonce is optional and defends against
replayed proofs (see [Replay attacks](./SECURITY.md#replay-attacks)): the
combiner sends each shareholder a fresh nonce, e.g. from `randomNonce()`, and
passes them to `recoverPublic` by index. A single packet is verified by
`parseSchnorrPacket(ctx, packet, { algorithm, nonce })`.

`recoverPublic` throws `InvalidPublicShare` at the first proof that fails, and
`InvalidInput` on fewer than `t` packets, on indexes that are not distinct
positive integers, and at the first malformed packet. It interpolates over all
packets whose proofs verify, not only `t` of them, which gives the same result
for any `t` of them as long as the shares lie on one polynomial of degree
`t - 1`. A share off that polynomial but validly proven distorts the result,
and only the dealer's commitments reveal it (see
[VSS](#verifiable-secret-sharing)).

> **Warning**
> Recovery does not check that the public shares stem from a Shamir sharing;
> it only checks that each shareholder knows its secret share.
> `combinePublicShares` skips even that check.

To identify every cheating shareholder instead of aborting at the first:

```js
const { recovered, blame } = await recoverPublic(ctx, packets, t, { errorOnInvalid: false });
if (blame.length > 0) {
  // hold the shareholders of these public shares accountable
}
```

`blame` lists the public shares, with their indexes, whose proofs fail or whose
packets are malformed, and the result is interpolated over the others. If fewer
than `t` remain, it throws `InvalidPublicShare`; invalid or duplicate indexes
still throw `InvalidInput`, since they cannot be attributed to one shareholder.
Always check `blame` with this option.

## NIZK proofs

[`vsslib/nizk`](./src/nizk.ts) proves knowledge of discrete logs satisfying
linear relations, `v_i = Π_j u_ij ^ x_j`, made non-interactive by the
Fiat-Shamir transform over a choice of hash function. Schnorr packets use its
discrete-log proofs; protocols can use it for their own statements.

```js
import { nizk } from "vsslib/nizk";

const protocol = nizk(ctx, "sha256");
const x = await ctx.parseScalar(secret);
const proof = await protocol.proveDlog(x, { u: ctx.generator, v: y }, nonce);
const valid = await protocol.verifyDlog({ u: ctx.generator, v: y }, proof, nonce);
```

Besides discrete logs (`proveDlog`), it proves equality of discrete logs, i.e.
Diffie-Hellman tuples (`proveDDH`), and generic linear relations
(`proveLinear`), each with its `verify` counterpart. The optional `nonce` binds
a proof to a session (see [Replay attacks](./SECURITY.md#replay-attacks)), and
`extras` to further public context, e.g. the share index in Schnorr packets.
