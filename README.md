# vsslib

Interfaces for Verifiable Secret Sharing (VSS) in TS/JS

:warning: **This library requires security audit. Use at your own risk for
the moment.**

Vsslib provides modular building blocks for implementing threshold-cryptographic protocols
based on Verifiable Secret Sharing (VSS), e.g., Distributed Key Generation (DKG) schemes.

## Quick example

**Local setup**

Involved parties agree on a common cryptosystem.

```js
import { initBackend } from "vsslib";

// Initiate cryptosystem instance over the ED25519 elliptic curve
const ctx = initBackend("ed25519");
```

**Dealer's side**
```js
import { shareSecret, createFeldmanPackets } from "vsslib";

// Generate a Shamir (5, 3)-sharing for some uniformly random secret
const { sharing } = await shareSecret(ctx, 5, 3);

// Generate verifiable packets for the totality of secret shares
const { packets, commitments } = await createFeldmanPackets(sharing);
```

Broadcast the commitments and send the packets to the respective shareholders
in private.

**Shareholders' side**

```js
import { parseFeldmanPacket, InvalidSecretShare } from "vsslib";

// Extract and verify secret share from received packet
try {
  const { share } = await parseFeldmanPacket(ctx, commitments, packet, t);
  // Store retrieved share locally
  ...
} catch (err) {
  if (err instanceof InvalidSecretShare) {
    // Follow rejection policy as specified by context
    ...
  } else {
    ...
  }
}
```

See [`examples`](./examples/dkg.ts) for complete flows of SSS, VSS and DKG.

## Overview

Vsslib provides modular building blocks for implementing threshold-cryptographic protocols
based on Shamir's Secret Sharing (SSS). It focuses on primitives that make the
sharing process verifiable on behalf of the involved parties
([Feldman](#feldman-scheme-1) and [Pedersen](#pedersen-scheme-1) VSS schemes)
and as such applicable in contexts with zero or low trust assumptions.

### <a name="backend-overview"></a>Backend

Vsslib is designed to be agnostic with respect to the underlying cryptosystem
and to admit pluggable backends.
It abstracts away algebraic details by internally interacting with a generic cryptosystem interface,
which backend implementations are expected to conform with.

Vsslib comes with several backends based on
[`noble-curves`](https://github.com/paulmillr/noble-curves),
but any implementation wrapped with the prescribed interface
should do the job, provided that it
- operates over a group of prime order,
- gives every element, including the neutral one, a unique encoding,
- rejects elements outside the prime-order subgroup,
- hashes to group elements of unknown discrete log, and
- samples scalars uniformly up to negligible bias.

Refer to [`vsslib/backend`](./src/backend/abstract.ts) for details.

### <a name="security-overview"></a>Security

:warning: **This library requires security audit. Use at your own risk for the moment.**

See [here](#security-main) for details.

## Table of contents
* [Installation](#installation)
* [Usage](#usage)
  * [Preliminaries](#preliminaries)
    * [Cryptosystem setup](#cryptosystem-setup)
    * [Secret generation](#secret-generation)
  * [Shamir's Secret Sharing (SSS)](#shamir-secret-sharing)
    * [Sharing the secret](#sharing-the-secret)
    * [Basic sharing interface](#basic-sharing-interface)
    * [Combining operations](#combining-operations)
  * [Verifiable Secret Sharing (VSS)](#verifiable-secret-sharing)
    * [Feldman scheme](#feldman-scheme-1)
    * [Pedersen scheme](#pedersen-scheme-1)
  * [Verifiable public recovery](#verifiable-public-recovery)
    * [Generation of packets](#generation-of-packets)
    * [Recovery operation](#recovery-operation)
* [Security](#security)
* [Performance](#performance)
  * [Horner's method](#horner-method)
  * [Common denominator](#common-denominator)
  * [Measurement setup](#measurement-setup)
* [Development](#development)

# Installation

```
npm install vsslib
```

Requires Node.js 20.19 or later, or a browser through a bundler such as esbuild,
Vite or webpack. The library uses no Node APIs at runtime: it hashes with
[`noble-hashes`](https://github.com/paulmillr/noble-hashes) and samples
randomness with `crypto.getRandomValues`, which every modern browser and
Node.js provide. The package is built as CommonJS, so loading it in a browser
without a bundler, e.g. from a CDN as an ES module, is not supported yet. See
[Browsers](#browsers) for the security implications.

# Usage

## Preliminaries

Vsslib operates over discrete-log based cryptosystems agnostically and you will need
to carry an instance of the respective backend in order to interact with the
library API.

### Cryptosystem setup

Vsslib provides out-of-the box several backends that can be initialized as follows.

```js
import { initBackend } from "vsslib";

const ctx = initBackend("ed25519");
  ```

The currently provided backends are the following.

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

On the curves with a cofactor, points outside the prime-order subgroup are rejected.
SEC1 points are accepted only in compressed form, with the single byte `0x00` for the point
at infinity; uncompressed and hybrid encodings are rejected.
Scalars are encoded little-endian with fixed width on every backend, so secret keys of the
SEC1 curves, conventionally big-endian, must be byte-reversed when exchanged with other libraries.
Pedersen bases are derived with RFC 9380 hash-to-curve, except on `jubjub`, which uses the
Zcash group hash.

> **Note**
> You can use any custom or other implementation,
provided that it conforms to or has been wrapped with the internally
prescribed interface.
Refer to [`vsslib/backend`](./src/backend/abstract.ts) for details.

### Secret generation

Generate a keypair in raw-bytes mode as follows.

```js
import { randomSecret } from "vsslib";

const { secret, publicBytes } = await randomSecret(ctx);
```

> **Note** 
> `secret` is the little-endian representation of a uniformly random scalar
modulo the underlying group order. `publicBytes`
is the byte representation of the respective group element.

#### Extraction of public counterpart

```js
import { extractPublic } from "vsslib";

const publicBytes = await extractPublic(ctx, secret);
```

> **Warning**
> Throws error if `secret` is not a valid byte representation
with respect to the underlying cryptosystem.

## <a name="shamir-secret-sharing"></a>Shamir's Secret Sharing (SSS)

### Sharing the secret

Generate a `(n, t)`-sharing of a given secret as follows.

```js
import { shareSecret } from "vsslib";

const { sharing } = await shareSecret(ctx, n, t, secret);
```

> **Warning**
> Throws error if the condition `1 <= t <= n < q` is violated, where `q` stands
> for the underlying group order, or the provided `secret` is not a valid byte
> respresentation with respect to the underlying cryptosystem.

If not provided, the secret is created on the fly.

```js
const { secret, sharing } = await shareSecret(ctx, n, t);
```

#### Sharing with predefined shares

Generate a `(n, t)`-sharing with up to `t-1` predefined shares as follows.

```js
const { secret: value1 } = await randomSecret(ctx);
const { secret: value2 } = await randomSecret(ctx);
...

const { sharing } = await shareSecret(ctx, n, t, secret, [
  { index: 1, value: value1 },
  { index: 2, value: value2 },
  ...
])
```

> **Warning**
> Throws error if the predefined shares are not less than `t`, or any of the
> provided indices in not in the range `(0,..., t - 1]` or is repeated, or any of the provided
> values is not a valid byte representation with respect to the underlying
> cryptosystem.

### Basic sharing interface


```js
// Access the original secret
const secret = sharing.getOriginalSecret();

// Access all secret shares
const secretShares = await sharing.getSecretShares();

// Access all public shares
const publicShares = await sharing.getPublicShares();

// Access the i-th share
const { secretShare, publicShare } = await sharing.getShare(i);
```

Access the public counterpart of a secret share as follows.

```js
import { extractPublic } from "vsslib";

const publicShare = {
  value: await extractPublic(ctx, secretShare.value),
  index: secretShare.index,
};
```

### Combining operations

#### Combination of secret shares

Combine at least `t` secret shares in the sense of interpolation as follows.

```js
import { combineSecretShares } from "vsslib";

const combinedSecret = await combineSecretShares(ctx, secretShares, t);
```

> **Warning**
> Throws `vsslib.InvalidInput` if less than `t` shares are provided.

#### Combination of public shares

Combine at least `t` public shares using interpolation in the exponent as
follows.

```js
import { combinePublicShares } from "vsslib";

const combinedPublic = await combinePublicShares(ctx, publicShares, t);
```

> **Warning**
> Throws `vsslib.InvalidInput` if less than `t` shares are provided.

#### Lagrange coefficients

The combining operations weigh each share by the Lagrange coefficient at zero
of its index with respect to the indexes of all combined shares. Protocols that
combine shares by themselves can compute these coefficients, as bigints modulo
the group order, as follows.

```js
import { computeLambda, computeLambdas } from "vsslib";

const lambdas = computeLambdas(ctx, [1, 3, 4]);   // one per index, in order
const lambda = computeLambda(ctx, 3, [1, 3, 4]);  // that of index 3 only
```

Prefer `computeLambdas` when all coefficients are needed, since it inverts a
single value for all of them (see [Common denominator](#common-denominator)).

> **Warning**
> Both throw `vsslib.InvalidInput` if the indexes are not distinct positive
> safe integers below the group order, and `computeLambda` also if `index` is
> not among them.

## <a name="verifiable-secret-sharing"></a>Verifiable Secret Sharing (VSS)

In practice, shareholders need to defend
against malicious dealers and verify the consistency of their respective
shares, i.e., ensure that they have indeed occured from the same sharing.
This is attained by means of additional information
attached to the individual shares and used to verify
them against some public quantity related to the sharing process.
Verifiable Secret Sharing (VSS) schemes extend Shamir's Sharing by including
this information to the share packets.

Vsslib provides implementations of the
[Feldman](#feldman-scheme-1) and [Pedersen](#pedersen-scheme-1) VSS schemes,
which are the most widely used in practice. Verifiable packets
are directly extracted from the sharing instance.

> **Warning**
> Correctly applying VSS when implementing DKG protocols is out of the library's scope.
In particular, it is the user's responsibility to handle verification errors
appropriately adhering to the prescribed complaint policy and ensure that only
non-byzantine parties end up with a secret share.

### <a name="feldman-scheme-1"></a>Feldman scheme

#### Generation of Feldman commitments and packets

Given a sharing,
generate Feldman commitments and verifiable packets for the totality of secret
shares as follows.

```js
import { createFeldmanPackets } from "vsslib";

const { packets, commitments } = await createFeldmanPackets(sharing);
```

> **Note**
> `commitments` are intended for broadcast while `packets`
> are sent to the respective shareholders in private.

#### <a name="verification-feldman"></a>Verification and extraction of secret share

Extract and verify secret share from the received packet as follows.

```js
import { parseFeldmanPacket } from "vsslib";

const { share } = await parseFeldmanPacket(ctx, commitments, packet, t);
```

This throws `vsslib.InvalidSecretShare` if the included share is found to
be invalid against the provided commitments, or if the number of commitments
differs from the agreed threshold `t`. You will usually have to handle
this error in order to adhere to some specified rejection policy:

```js
import { InvalidSecretShare } from "vsslib";

try {
  const { share } = await parseFeldmanPacket(ctx, commitments, packet, t);
  // Store locally the retrieved secret share
  ...
} catch (err) {
  if (err instanceof InvalidSecretShare) {
    // Follow rejection policy as specified by context
    ...
  } else {
    ... 
  }
}
```

#### Standalone verification of secret share

If already available through different channels, a secret share can be directly
verified against the commitments as follows.

```js
import { verifyFeldmanCommitments, InvalidSecretShare } from "vsslib";

try {
  await verifyFeldmanCommitments(ctx, commitments, share, t);
} catch (err) {
  if (err instanceof InvalidSecretShare) {
    // Follow rejection policy as specified by context
    ...
  } else {
    ... 
  }
}
```

### <a name="pedersen-scheme-1"></a>Pedersen scheme

Involved parties agree first on a public group element to be used as Pedersen base.
Derive it by hashing a public seed, so that no one knows its discrete log
with respect to the generator:

```js
import { derivePedersenBase } from "vsslib";

const pedersenBase = await derivePedersenBase(ctx, seed);
```

The seed is optional and can be any bytestring agreed upon by the parties, e.g.,
a session identifier; if omitted, a fixed default base is derived.

> **Warning**
> Do not use a base generated by one of the parties, e.g. with `randomPublic`.
> Whoever knows the discrete log of the base can open commitments to arbitrary
> values, i.e., distribute invalid shares that pass verification.

#### Generation of Pedersen commitments and packets

Given a sharing, generate Pedersen commitments and verifiable packets for the totality of secret
shares as follows.

```js
import { createPedersenPackets } from "vsslib";

const { packets, commitments } = await createPedersenPackets(sharing, pedersenBase);
```

> **Note**
> `commitments` are intended for broadcast while `packets`
> are sent to the respective shareholders in private.

#### <a name="verification-pedersen"></a>Verification and extraction of secret share

Extract and verify secret share from the received packet as follows.

```js
import { parsePedersenPacket } from "vsslib";

const { share, binding } = await parsePedersenPacket(ctx, commitments, pedersenBase, packet, t);
```

> **Note**
> The included secret `binding` is implicitly used during verification and can be
> discarded.

This throws `vsslib.InvalidSecretShare` if the included share is found to
be invalid against the provided commitments, or if the number of commitments
differs from the agreed threshold `t`. You will usually have to handle
this error in order to adhere to some specified rejection policy:

```js
import { InvalidSecretShare } from "vsslib";

try {
  const { share, binding } = await parsePedersenPacket(ctx, commitments, pedersenBase, packet, t);
  // Store locally the retrieved secret share
  ...
} catch (err) {
  if (err instanceof InvalidSecretShare) {
    // Follow rejection policy as specified by context
    ...
  } else {
    ... 
  }
}
```

#### Standalone verification of secret share

If already available through different channels, a secret share can be directly
verified along with its binding against the commitments as follows.

```js
import { verifyPedersenCommitments, InvalidSecretShare } from "vsslib";

try {
  await verifyPedersenCommitments(ctx, commitments, pedersenBase, share, binding, t);
} catch (err) {
  if (err instanceof InvalidSecretShare) {
    // Follow rejection policy as specified by context
    ...
  } else {
    ... 
  }
}
```

## Verifiable public recovery

When reconstructing the public counterpart of a shared secret, the
combiner usually needs to verify the aggregated public shares. Specifically, acclaimed
shareholders may be expected to prove knowledge of their respective secret shares
in a zero-knowledge (ZK) fashion (e.g., for public key certification purposes).

> **Warning**
> This operation does not verify per se the consistency of the public shares;
> specifically, it does not ensure that they combine to the public counterpart
> of a secret that has indeed been distributed by means of Shamir's sharing.

> **Note**
> Refer to Sec. [Combination of public shares](#combination-of-public-shares) for an
> operation that bypasses verification of public shares.

### Generation of packets

Create a verifiable packet for a secret share as follows.

```js
import { createSchnorrPacket } from "vsslib";

const packet = await createSchnorrPacket(ctx, share, { algorithm: "sha256" });
```

This consists of the public share and a NIZK (Schnorr) proof-of-knowledge of
the secret counterart.
The optional `algorithm` parameter specifies the hash function used for proof
generation (defaults to SHA256).

>  **Note**
> Involved shareholders are expected to use the same hash function.

#### Nonce inclusion

The combiner may need to defend against replay attacks by
maintaining some kind of state between itself and individual shareholders.
It can do so by storing a nonce per session and shareholder.
Upon receiving its respective nonce through some secure channel, the
shareholder includes it in packet generation as follows.

```js
const packet = await createSchnorrPacket(ctx, share, { ..., nonce });
```

### Recovery operation

After aggregating the packets, the combiner can recover the group public key as
follows.

```js
import { recoverPublic } from "vsslib";

const { recovered } = await recoverPublic(ctx, packets, t, { algorithm: "sha256" });
```

This verifies the attached Schnorr proofs against the respective public
shares and combines the latter in the sense of interpolation.
The optional `algorithm` parameter specifies
the hash function used for the verification of individual
proofs (defaults to SHA256).

The operation throws `vsslib.InvalidPublicShare`
upon the first proof that fails to verify.
It throws `vsslib.InvalidInput` if less than `t` packets are provided, and
also `vsslib.InvalidInput` if the packet indexes are not distinct
positive integers.
You will usually have to handle errors in order
to adhere to some specified rejection policy:

```js
import { InvalidPublicShare, InvalidInput } from "vsslib";

try {
  const { recovered } = await recoverPublic(ctx, packets, t, { algorithm: "sha256" });
  ...
} catch (err) {
  if (err instanceof InvalidPublicShare) {
    // Abort and follow policy as specified by context
    ...
  } else if (err instanceof InvalidInput) {
    // Abort and follow policy as specified by context; raised upon
    // malformed or duplicate indexes, or insufficient number of packets
    ...
  } else {
    ...
  }
}
```


#### Nonce-based recovery

If certain shareholders are expected to have included a nonce when generating
their packets, these must be explicitly passed into the recovery operation so
that the respective proofs verify.

```js
try {
  const { recovered } = await recoverPublic(ctx, packets, t, {
    ...,
    nonces: {
      1: ...,
      2: ...,
      ...
    }
  });
  ...
} catch (err) {
  if (err instanceof InvalidPublicShare) {
    // Abort and follow policy as specified by context
    ...
  } else {
    ...
  }
}
```

#### Recovery with accurate blaming

For security investigation purposes, the combiner may want to trace
cheating shareholders. This presupposes that the recovery operation completes
irrespective of potential verification failures so that
malicious shareholders can be listed in a blame index.

```js
const { recovered, blame } = await recoverPublic(ctx, packets, t, { ..., errorOnInvalid: false });

if (blame.length > 0) {
  // Hold cheating shareholders accountable according to specified policy
  ...
}
```

This returns the computation result along with a list `blame`,
containing the public shares of cheating shareholders.
If less than `t` packets remain valid, it throws `vsslib.InvalidPublicShare`,
since the remaining shares would interpolate to a wrong result.
Malformed or duplicate indexes still throw `vsslib.InvalidInput`, since they
cannot be attributed to a single shareholder.

> **Warning**
> Make sure to always check the `blame` index when using the `errorOnInvalid: false` option.

# <a name="security-main"></a>Security

:warning: **This library requires security audit. Use at your own risk for the moment.**

### <a name="side-channel-attacks"></a>Side-channel attacks

Strict resistance against side-channel attacks cannot be attained in JavaScript.
The language is garbage-collected and just-in-time compiled, and its `BigInt`
arithmetic, which vsslib and its backends use for scalars, makes no promise of
running in time independent of the operands. Secret values may moreover be
copied around the heap beyond the control of any library. Vsslib therefore aims
at algorithmic precautions which remove the known leaks of its own code and keep
the remaining exposure low, and which are described below. They reduce, but do
not eliminate, what a timing or memory observer can learn; applications guarding
high-value, long-lived keys against co-located attackers should consider a
native implementation instead.

Comparisons involving secrets run in constant time. A naive comparison of two
values returns as soon as they differ, so that its running time reveals where
they differ and, over repeated attempts, the values themselves. Since vsslib
admits only canonical encodings of scalars and group elements, two values are
equal exactly when their encodings are, which `isEqualSecret`, `isEqualPublic`
and `isKeypair` compare byte by byte, accumulating the differences without
early exit. The inputs are parsed beforehand, so that invalid encodings are
still rejected. For the same reason, scalars are encoded to bytes by
bounds-checking them against the fixed scalar length, rather than measuring
their size by conversion to a string, which would run in variable time and
leave a copy of the secret on the heap.

Exponentiation by secret scalars, such as shares, coefficients of the sharing
polynomial, Pedersen bindings, secret keys and NIZK nonces, is the most exposed
operation, since it is long and its timing depends on the scalar. The
elliptic backends rely on [`noble-curves`](https://github.com/paulmillr/noble-curves),
which multiplies with a fixed sequence of operations and additionally blinds
the scalar with a random multiple of the group order. Blinding is however
applied only on curves of cofactor one (`secp256k1`, `p256`, `p384`, `p521`),
whereas on the cofactored curves it covers only noble's own base point, i.e.,
the generator of `ed25519`, `ed448`, `jubjub` and `ristretto255`; on `decaf448`
it covers no point at all. A leak in an unblinded multiplication accumulates
over repeated calls with the same scalar, e.g., when a shareholder verifies its
long-lived Pedersen binding, and partial leakage of NIZK nonces over many proofs
is known to suffice for lattice-based key recovery. Vsslib performs every
exponentiation by a secret scalar through `Group.expSecret`, which uses the
backend's exponentiation directly only where it blinds natively, as reported by
`Group.blindsNatively`. Otherwise it splits the scalar as
`P^s = (P^r)^(s/r)` for a freshly sampled `r`, so that each of the two
multiplications sees a uniformly random scalar independent of `s`, which keeps
leakage from accumulating across calls. The split is multiplicative because the
additive alternative `P^r * P^(s - r)` requires reducing `s - r`, which branches
on whether `s < r` and would thereby leak an estimate of `s` over many calls.
Since modular inversion runs in variable time as well, `r` is inverted as
`u / (r * u)` for a second fresh random `u`, so that the inversion only sees a
value independent of `r`. The split
costs a second multiplication and an inversion: Pedersen dealing becomes up to
about twice as slow on the Edwards curves, and every secret operation about
twice as slow on `decaf448`, whereas the curves of cofactor one are unaffected.
`Group.exp` remains in use for public scalars only, such as Lagrange
coefficients and NIZK challenges and responses. Share indexes go through
`Group.expPublic` instead, which the elliptic backends implement by noble's
variable-time multiplication: raising the commitments to powers of the share
index, which is small and public, then costs a few doublings instead of a full
constant-time multiplication, which shortens verification by 31% to 95%
depending on the curve (see [Horner's method](#horner-method)). Custom backends inherit the split and should override `blindsNatively`
only for points their exponentiation blinds; `expPublic` defaults to `exp`, and
an override may run in variable time, since it never receives secrets.

Memory hygiene is limited by the language as well. `BigInt` values are
immutable and cannot be overwritten, so the scalars vsslib computes with stay in
memory until garbage collection, where heap snapshots, core dumps or swap may
expose them. Vsslib wipes the byte buffers it controls, namely the random bytes
from which secret scalars and nonces are sampled. The byte arrays it returns,
such as secrets, secret shares and bindings, belong to the caller, who should
overwrite them, e.g. with `fill(0)`, once they are no longer needed, and drop
references to objects holding secrets, such as a `ShamirSharing`, as soon as
possible. Finally, the remaining arithmetic on secrets, i.e., evaluation of the
sharing polynomial, interpolation over predefined shares, combination of shares
and computation of NIZK responses, operates on `BigInt`
and is not constant-time in principle; since it involves uniformly random
full-width values, the information exposed by its timing is expected to be
small, and its elimination requires a fixed-width scalar representation, which
is planned.

### <a name="browsers"></a>Browsers

In a browser, vsslib shares the JavaScript engine with whatever else the page
loads, so the precautions above meet a stronger adversary. Scripts of the same
origin, including third-party dependencies and analytics, can read any value
reachable from the page, secrets and shares included, and browser extensions
with access to the page can do the same. Cross-origin code can still measure
timing, e.g. through shared caches and high-resolution timers, which isolation
mechanisms of the browser such as site isolation and cross-origin isolation
mitigate, but do not remove. Applications handling secrets in the browser should
keep them in a dedicated context, e.g. a Web Worker or a separate origin with a
strict Content Security Policy, load vsslib from a pinned and integrity-checked
bundle, and wipe the returned byte arrays as described above. Randomness comes
from `crypto.getRandomValues`, which browsers back by the operating system's
generator; it limits a single call to 65536 bytes, so that `randomNonce` accepts
sizes from 1 to 65536 bytes.

### <a name="input-validation-overview"></a>Input validation

Vsslib's interface operates with the byte representations of scalars and group
elements, taking care to always ensure that the involved bytestrings are valid
representations with respect to the underlying cryptosystem.
Group elements are moreover required to lie in the prime-order subgroup, so
that points with a small-order component are rejected.
Scalars are required to be canonically encoded, i.e., little-endian with fixed
length and value less than the group order.

### <a name="nizk-overview"></a>Support for NIZK proofs

Threshold-cryptographic security against malicious shareholders
is usually attained by means of non-interactive zero-knowledge (NIZK) proofs
for contextual statemenets.
Vsslib provides NIZK infrastructure ([`vsslib/nizk`](./src/nizk.ts))
for proving knowledge of generic discrete-log based linear relations
over arbitrary groups and hash functions.

#### <a name="replay-attacks-overview"></a>Defence against replay attacks

In practice, plain usage of NIZK proofs is usually susceptible to replay
attack. Vsslib allows inclusion of nonces when generating a NIZK proof, capable of
maintaining state between the verifier and the involved
provers. A nonce can be any bytestring,
e.g., cryptographically secure random bytes, unique session identifiers,
synchronized counters, or combinations thereof.
It is the user's responsibility to ensure that its design is secure in the
particular application context.

# <a name="performance"></a>Performance

### <a name="horner-method"></a>Horner's method

Horner's rule evaluates a polynomial of degree `t - 1` with `t - 1`
multiplications and additions, as `a_0 + x(a_1 + x(a_2 + ...))`, without
computing powers of `x`. Vsslib evaluates polynomials at every share index
`i = 1, ..., n` in two places: in the exponent, when verifying VSS commitments,
and over scalars, when computing the shares from the sharing polynomial. The
work on these places sped up the verification of VSS packets considerably, but
most of the gain does not come from Horner's rule itself. Verification already
used it, and became faster because each of its steps became cheaper, whereas
Horner's rule over the sharing polynomial gains a lot in relative terms on an
operation that was cheap to begin with. The causes are described separately
below, followed by the measured changes of median running time against the
previous implementation, over `n = 10, 50` shares and thresholds `t = 5, 25`:

| operation | `ed25519`, `decaf448` | `secp256k1`, `p521` | cause |
| --- | ---: | ---: | --- |
| verify/parse Feldman packets | -31% to -61% | -89% to -95% | [variable-time steps](#horner-variable-time) |
| verify/parse Pedersen packets | -22% to -54% | -73% to -91% | [variable-time steps](#horner-variable-time) |
| `getSecretShares` | -78% to -93% | -78% to -93% | [Horner's rule](#horner-sharing-polynomial) |
| `createFeldmanPackets` (n = 50) | up to -23% | up to -22% | [Horner's rule](#horner-sharing-polynomial) |
| `shareSecret` (t = 5 / t = 25) | -45% / -90% | -45% / -90% | [no interpolation](#horner-sampling) |

Operations dominated by exponentiations by secret scalars or Lagrange
coefficients, such as `getPublicShares`, `createPedersenPackets` and the
combination of shares, are unchanged within noise.

#### <a name="horner-variable-time"></a>Variable-time steps in commitment verification

A share with index `i` is verified against the commitments `C_0, ..., C_(t-1)`
by computing `C_0 * C_1^i * C_2^(i^2) * ... * C_(t-1)^(i^(t-1))`, which vsslib
already did by Horner's rule as `C_0 * (C_1 * (C_2 * ...)^i)^i`. This had
however no effect on the cost, because the steps went through `Group.exp`,
which noble runs in constant time, with the same sequence of operations for
every scalar up to the group order. Raising to the small index `i` then costs as
much as raising to the large `i^j`, so that both forms cost about one full
multiplication per commitment. The steps now go through `Group.expPublic`, which the elliptic
backends implement by noble's variable-time multiplication, whose cost grows
with the length of the scalar. Each step then costs a few doublings and
additions, since `i` has only a few bits. This is what makes verification
faster: measured on its own, this change accounts for nearly all of the gains of
verification in the table. Horner's rule is what makes it pay off
in full, since it keeps every scalar as short as `i`; with the powers `i^j`
instead, the scalars would grow by the length of `i` per term up to the full
length of the order. Variable time is safe here, since the index and the
commitments are public (see [Side-channel attacks](#side-channel-attacks)), and
`Group.expPublic` is used nowhere else.

For example, parsing and verifying a Feldman packet with `n = 50, t = 25` takes
3.32 ms instead of 46.6 ms on `secp256k1`. The gain is smaller on the Edwards
curves (20.3 ms instead of 29.7 ms on `ed25519`), because each parsed commitment
is checked to lie in the prime-order subgroup, a full multiplication that
remains.

#### <a name="horner-sharing-polynomial"></a>Horner's rule over the sharing polynomial

The sharing polynomial used to be evaluated at each share index in the
barycentric form of the interpolating polynomial, with one modular inversion
per interpolation point at every call. It is now evaluated by Horner's rule
over its coefficients, with `t - 1` multiplications and a single reduction
modulo the order, which cuts the time of `getSecretShares` by 78% to 93%. This is the
gain of Horner's rule proper, but it concerns arithmetic on scalars, which is
cheap compared to group operations: with `n = 50, t = 25` on `ed25519`,
`getSecretShares` takes 92 µs instead of 1.21 ms, whereas `getPublicShares`,
which raises the generator to each share, takes 11 ms. It is visible in
`createFeldmanPackets`, which evaluates the polynomial alongside cheaper group
operations.

#### <a name="horner-sampling"></a>Sampling instead of interpolation

`shareSecret` used to construct the sharing polynomial by interpolating the
secret at `0` and random values at `1, ..., t - 1`. Without predefined shares,
it now samples the coefficients directly, with the secret as constant term,
which yields the same distribution without interpolation, so that `shareSecret`
takes 45% less time at `t = 5` and about 90% less at `t = 25`. This is unrelated to
Horner's rule, and again concerns scalar arithmetic in the microsecond range.
With predefined shares, the polynomial is still interpolated, now building the
Lagrange basis in quadratic instead of cubic time; this case was not
benchmarked.

### <a name="common-denominator"></a>Common denominator

The Lagrange coefficient of index `x_i` with respect to the indexes
`x_1, ..., x_k` of the combined shares is the product of `x_j / (x_j - x_i)`
over all `j` other than `i`. The combining operations used to compute each
coefficient separately and to invert every difference modulo the order, i.e.
`k(k - 1)` modular inversions for `k` shares, each a run of the extended
Euclidean algorithm on big integers. The coefficients are now written over a
common denominator, as `N / (x_i D_i)` with `N` the product of all indexes and
`D_i` the product of the differences, and the denominators of all coefficients
are inverted together by Montgomery's trick, with a single inversion and three
multiplications per coefficient, followed by one more to multiply by `N`.
Since indexes are small integers, these products are reduced modulo the order
only once they outgrow it by 256 bits: reducing at every step made them 2-3
times slower, and not reducing at all much slower for thousands of shares. Measured changes of median running time of
`combineSecretShares` against the previous implementation, with `n = 100`
shares:

| threshold | `ed25519` | `decaf448` | `secp256k1` | `p521` |
| ---: | ---: | ---: | ---: | ---: |
| 5 | -15% | -17% | -12% | -22% |
| 25 | -84% | -80% | -84% | -80% |
| 50 | -91% | -91% | -91% | -90% |
| 100 | -94% | -94% | -93% | -94% |

For example, combining 100 secret shares on `ed25519` takes 662 µs instead of
10.4 ms. This concerns arithmetic on scalars only. `combinePublicShares` and
`recoverPublic` are unchanged within noise, since raising each share to its
coefficient costs far more than computing the coefficient: with `t = 25` on
`ed25519`, `combinePublicShares` takes 39 ms, of which the coefficients took
about 0.5 ms.

`shareSecret` with predefined shares interpolates `t` points, which inverts the
`t` denominators of the Lagrange basis; these are now inverted in a batch too.
Measured with a separate script, since the benchmarks do not cover predefined
shares, it takes 10-25% less time at `t = 25` and 43-55% less at `t = 50, 100`.

### <a name="measurement-setup"></a>Measurement setup

The figures were measured with the [benchmarks](#benchmarks), 5 runs per side,
on an Intel Core i5-12450H pinned to its performance cores (`--cpus 0-7`) with
the `powersave` governor, under Ubuntu 24.04.5 (Linux 6.8), Node.js 22.22.1 and
`@noble/curves` 2.4.0. Absolute times depend on the machine; the relative
changes are what to compare. To reproduce, save baselines with `--save` before
the changes and compare after them. For Horner's method:

```
$ ./bench.sh -m shamir,feldman,pedersen -s ed25519,decaf448,secp256k1,p521 \
    -n 10,50 -t 5,25 --cpus 0-7 -r 5 --compare <baseline>
```

For the common denominator:

```
$ ./bench.sh -o "combine*,recoverPublic" -s ed25519,decaf448,secp256k1,p521 \
    -n 100 -t 5,25,50,100 --cpus 0-7 -r 5 --compare <baseline>
```

# Development

```
$ ./test.sh --help                  # tests, over all systems unless -s <SYSTEM>
$ ./bench.sh --help                 # benchmarks of the high-level operations
$ npx tsx examples/dkg.ts --help    # also sss.ts and vss.ts
$ npm run lint
$ npm run typecheck                 # library, tests, benchmarks and examples
$ npm run build
$ npm run docs                      # API reference in docs/
```

## Tests

Tests run on Node's built-in test runner (`node:test`), with tsx compiling the
sources; `./test.sh` also writes a JUnit report to `coverage/junit.xml` for CI.

## Layout

[`src/operations`](./src/operations/index.ts) holds the library operations,
one module per scheme (`shamir`, `feldman`, `pedersen`, `recovery`, plus
`secrets`), each with both directions of the scheme, e.g., packet creation and
parsing. They build on the core modules of `src` (backends, NIZK proofs,
interpolation), which never import from them. Tests in `tests/operations`
mirror these modules.

## Examples

[`examples`](./examples/dkg.ts) holds complete flows: SSS, VSS with verifiable public
recovery, and DKG built on top of the latter. They are reference
implementations, with the parties of every step marked, and are also run by
the tests.

## Browser check

[`tests/browser.spec.ts`](./tests/browser.spec.ts) bundles the entry points of
the library for the browser with esbuild and fails on any Node module, also one
required inside `try`, and on any reference to Node globals such as `Buffer` or
`process`. It then runs SSS, VSS with public recovery and NIZK proofs from the
bundle in a Node `vm` context that exposes only `crypto` and `TextEncoder`. It
thereby guards against Node APIs leaking into the library, but does not bundle
the compiled `dist`.

[`tests/browser/engines.ts`](./tests/browser/engines.ts) runs the same flows in
Chromium, Firefox and WebKit through `playwright-core`, which downloads no
browsers itself. CI runs it on schedules and on demand, in the Playwright image
that ships the browsers. Locally, after `npx playwright-core install`,

```
$ npm run test:browsers                         # BROWSERS=chromium,firefox to select
```

## Benchmarks

Benchmarks cover the high-level operations of the library only (no backends
or internals), each as the local computation of one party: the dealer, a
shareholder or the combiner. Complete protocol runs such as VSS or DKG are not
benchmarked, since no party computes them as a whole: the parties run in
parallel, and the rounds between them depend on the network and on how the
application implements the protocol. See `--help` for modules, parameter
sweeps, output formats, columns and baselines.

### Workers

Each run is a fresh `node` process that loads a bundle of the benchmarks and
the library sources, built by esbuild once per invocation with the target of
`dist` (`es2020`). Dependencies are left out of the bundle, so that node loads
the ESM-only `@noble/curves` and `@noble/hashes` natively, as it does for users
of `dist`. Running the sources through tsx instead would transform these
packages to CommonJS, which made their hashes up to 35 times slower. Baselines
record the runner, and comparisons warn against baselines taken through tsx.

### Statistics

Each case runs in fresh processes, repeated round-robin over the cases on
seeded inputs, and is reported as medians over runs; `range` shows how quiet
the machine was. A case counts as changed only if its median moved beyond the
tolerance and the runs of both invocations do not overlap; unchanged code
passes this by chance 10% of the time with the default 3 runs per side, and
below 1% with 5.

### CPUs

Runs record the machine conditions and comparisons warn when these differ.
Use the `performance` governor and, on CPUs with performance and efficiency
cores, pin the runs to one kind with `--cpus`; turbo boost, throttling and
background load are not controlled. Take the two sides of a comparison back to
back: under the `powersave` governor, the same code once measured twice as slow
an hour apart.

## Dependencies

`@noble/curves` and `@noble/hashes` are pinned exactly, so that installing
vsslib never resolves a noble release that was not tested with it; an
application that depends on another noble version gets a second copy. esbuild
is pinned within the `~0.28` range of tsx, so that both share one copy. CI runs
on a Node.js image pinned by digest (`.gitlab-ci.yml`). Nothing updates these
automatically; to bump them

1. `npm outdated` lists newer versions; `npm view <package> time` shows their
   release dates. Take a version only once it is at least 7 days old, which
   leaves time for a compromised release to be found and pulled.
2. Bump `@noble/curves` and `@noble/hashes` together: curves pins hashes exactly,
   so both must name the same version for npm to install one copy of hashes.
3. Bump esbuild together with tsx, within the range tsx accepts, and
   `playwright-core` together with the Playwright image of the `browsers` job,
   whose browsers must match it.
4. For the CI image, take the newest `22.x` tag and the digest of its index
   (see the comment in `.gitlab-ci.yml`).
5. Run `npm install`, check that `npm ls @noble/hashes esbuild` lists one
   version of each, and run `npm audit signatures`, lint, type check and tests.

## Publish

Update the CHANGELOG, then

```
$ npm version <patch|minor|major> -m "chore: release %s"
$ npm publish
$ git push --follow-tags
```

`npm publish` first runs lint, type check, tests and build (`prepublishOnly`),
and requires `npm login` or a token in `~/.npmrc`.
