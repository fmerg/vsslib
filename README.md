# vsslib

Interfaces for Verifiable Secret Sharing (VSS) in TS/JS

:warning: **This library requires security audit. Use at you own risk for
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
const { packets, commitments } = await sharing.createFeldmanPackets();
```

Broadcast the commitments and send the packets to the respective shareholders
in private.

**Shareholders' side**

```js
import { parseFeldmanPacket, InvalidSecretShare } from "vsslib";

// Extract and verify secret share from received packet
try {
  const { share } = await parseFeldmanPacket(ctx, commitments, packet);
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
should do the job. Refer to [`vsslib/backend`](./src/backend) for details.

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
* [Development](#development)

# Installation

```
npm install vsslib
```

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

The currently provided backends are  `ed25519`, `ed448` and `jubjub`.

> **Note**
> You can use any custom or other implementation,
provided that it conforms to or has been wrapped with the internally
prescribed interface.
Refer to [`vsslib/backend`](./src/backend) for details.

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
> provided indices in not in the range `(0,..., t - 1]`, or any of the provided
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
import { extractPublicShare } from "vsslib";

const publicShare = await extractPublicShare(ctx, secretShare);
```

### Combining operations

#### Combination of secret shares

Combine any collection of secret shares in the sense of interpolation as
follows.

```js
import { combineSecretShares } from "vsslib";

const combinedSecret = await combineSecretShares(ctx, secretShares);
```

This yields the original secret only if the number of provided shares is at least equal
to the threshold `t`.
In order to ensure that the operation completes only if at least `t` shares are
provided, make sure to pass the threshold parameter explicitly.

```js
const combinedSecret = await combineSecretShares(ctx, secretShares, t);
```

> **Warning**
> Throws error if less than `t` shares are provided.

#### Combination of public shares

Combine any collection of public shares using interpolation in the exponent as
follows.

```js
import { combinePublicShares } from "vsslib";

const combinedPublic = await combinePublicShares(ctx, publicShares);
```

This yields the public counterpart of the original secret only if
the number of provided shares is at least equal to the threshold `t`.
In order to ensure that the operation completes only if at least `t` shares are
provided, make sure to pass the threshold parameter explicitly.

```js
const combinedPublic = await combinePublicShares(ctx, publicShares, t);
```

> **Warning**
> Throws error if less than `t` shares are provided.

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
const { packets, commitments } = await sharing.createFeldmanPackets();
```

> **Note**
> `commitments` are intended for broadcast while `packets`
> are sent to the respective shareholders in private.

#### <a name="verification-feldman"></a>Verification and extraction of secret share

Extract and verify secret share from the received packet as follows.

```js
import { parseFeldmanPacket } from "vsslib";

const { share } = await parseFeldmanPacket(ctx, commitments, packet);
```

This throws `vsslib.InvalidSecretShare` if the included share is found to
be invalid against the provided commitments. You will usually have to handle
this error in order to adhere to some specified rejection policy:

```js
import { InvalidSecretShare } from "vsslib";

try {
  const { share } = await parseFeldmanPacket(ctx, commitments, packet);
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
  await verifyFeldmanCommitments(ctx, share, commitments);
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

Involved parties agree first on some public reference:

```js
import { randomPublic } from "vsslib";

const publicBytes = await randomPublic(ctx);
```

#### Generation of Pedersen commitments and packets

Given a sharing, generate Pedersen commitments and verifiable packets for the totality of secret
shares as follows.

```js
const { packets, commitments } = await sharing.createPedersenPackets(publicBytes);
```

> **Note**
> `commitments` are intended for broadcast while `packets`
> are sent to the respective shareholders in private.

#### <a name="verification-pedersen"></a>Verification and extraction of secret share

Extract and verify secret share from the received packet as follows.

```js
import { parsePedersenPacket } from "vsslib";

const { share, binding } = await parsePedersenPacket(ctx, commitments, publicBytes, packet);
```

> **Note**
> The included secret `binding` is implicitly used during verification and can be
> discarded.

This throws `vsslib.InvalidSecretShare` if the included share is found to
be invalid against the provided commitments. You will usually have to handle
this error in order to adhere to some specified rejection policy:

```js
import { InvalidSecretShare } from "vsslib";

try {
  const { share, binding } = await parsePedersenPacket(ctx, commitments, publicBytes, packet);
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
  await verifyPedersenCommitments(ctx, share, binding, publicBytes, commitments);
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

const { recovered } = await recoverPublic(ctx, packets, { algorithm: "sha256", threshold: t });
```

This verifies the attached Schnorr proofs against the respective public
shares and combines the latter in the sense of interpolation.
The optional `algorithm` parameter specifies
the hash function used for the verification of individual
proofs (defaults to SHA256).

The operation throws `vsslib.InvalidPublicShare`
upon the first proof that fails to verify.
The optional `threshold` parameter ensures that the operation completes only if
at least `t` packets are provided,
otherwise it throws `vsslib.InvalidInput` error.
You will usually have to handle errors in order
to adhere to some specified rejection policy:

```js
import { InvalidPublicShare, InvalidInput } from "vsslib";

try {
  const { recovered } = await recoverPublic(ctx, packets, { algorithm: "sha256", threshold: t });
  ...
} catch (err) {
  if (err instanceof InvalidPublicShare) {
    // Abort and follow policy as specified by context
    ...
  } else if (err instanceof InvalidInput) {
    // Abort and follow policy as specified by context; makes sense only
    // if the `threshold` parameter has been provided.
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
  const { recovered } = await recoverPublic(ctx, packets, {
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
const { recovered, blame } = await recoverPublic(ctx, packets, { ..., errorOnInvalid: false });

if (blame.length > 0) {
  // Hold cheating shareholders accountable according to specified policy
  ...
}
```

This returns the computation result along with a list `blame`,
containing the public shares of cheating shareholders.

> **Warning**
> Make sure to always check the `blame` index when using the `errorOnInvalid: false` option.

# <a name="security-main"></a>Security

:warning: **This library requires security audit. Use at your own risk for the moment.**

### <a name="side-channel-attacks"></a>Side-channel attacks

Constant-time operations have been applied where possible.
Strict resistance against side-channel-attacks is improssible to attain,
since JS is a garbage-collected and just-in-time compiled language.
This moreover depends crucially on the cryptographic
backend implementation.

### <a name="input-validation-overview"></a>Input validation

Vsslib's interface operates with the byte representations of scalars and group
elements, taking care to always ensure that the involved bytestrings are valid
representations with respect to the underlying cryptosystem.

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

# Development

### Examples

```
npx tsx examples/<file> --help
```

### Tests

```
$ ./test.sh --help
```

### Lint

```
$ npm run lint
```

### Build

```
$ npm run build
```

## Documentation

```
$ npm run docs
```
