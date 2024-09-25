# vsslib

Interfaces for Verifiable Secret Sharing (VSS) and Threshold Cryptography
in TS/JS

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
sharing process verifiable on behalf of involved parties
([Feldman](#feldman-scheme-1) and [Pedersen](#pedersen-scheme-1) VSS schemes)
and as such applicable in contexts with zero or low trust assumptions
(e.g., Distributed Key Generation (DKG) protocols).

### <a name="backend-overview"></a>Backend

Vsslib is designed to be agnostic with respect to the underlying cryptosystem
and to admit pluggable backends.
It abstracts away algebraic details by internally interacting with a generic cryptosystem interface,
which backend implementations are expected to conform with.

Vsslib comes with several backends based on
[noble-curves](https://github.com/paulmillr/noble-curves),
but any implementation wrapped with the prescribed interface
should do the job. Refer to section [Pluggable backend](#pluggable-backend) for details.

### <a name="interface-overview"></a>Interface

Vsslib exposes two separate APIs.

The [bytes](#shamir-secret-sharing) interface is intended
for applications where more freedom is required on how
to directly handle the secret bytes
(e.g., distributed generation of ephemeral secrets, or under the constraints imposed
by a pre-existing public-key API).

The "key" interface builds on top of a public-key API
([`vsslib/keys`](./src/keys)),
which exposes assymetric operations at the high-level and is compatible with a
ready-made solution for [threshold decryption](#threshold-decryption).

Both operate with the same sharing abstraction layer.

### <a name="security-overview"></a>Security

:warning: **This library requires security audit. Use at your own risk for the moment.**

See [Security](#security-main) for details.

#### <a name="selection-of-parameters-overview"></a>Remark on the selection of parameters

Vsslib is unopinionated on the selection of cryptographic parameters
(DL-cryptosystem, hash function for NIZK-proofs,
Elgamal encryption scheme, AES block-mode for hybrid encryption etc.), allowing complete freedom on how to
orthogonally combine them.

For example, the provided threshold decryption mechanism is operable with
plain Elgamal encryption even if this combination is per se insecure
against chosen-ciphertext attacks.
It is the user's responsibility to decide if the desired level of security
is attained in a particular context by other means.

## Table of contents

* [Installation](#installation)
* [Usage](#usage)
  * [Preliminaries](#preliminaries)
    * [Cryptosystem setup](#cryptosystem-setup)
    * [Secret generation](#secret-generation)
  * [Shamir's secret sharing (SSS)](#shamir-secret-sharing)
    * [Distributing the secret](#distributing-the-secret)
    * [Basic sharing interface](#basic-sharing-interface)
    * [Combination of secret shares](#combination-of-secret-shares)
    * [Combination of public shares](#combination-of-public-shares)
  * [Verifiable secret sharing (VSS)](#verifiable-secret-sharing)
    * [Feldman scheme](#feldman-scheme-1)
    * [Pedersen scheme](#pedersen-scheme-1)
  * [Verifiable public recovery](#verifiable-public-recovery)
    * [Verifiable share packets](#verifiable-share-packets)
    * [Recovery operation](#recovery-operation)
    * [Recovery with accurate blaming](#recovery-with-accurate-blaming)
  * [Key layer](#key-layer)
    * [Share extraction](#share-extraction)
    * [Partial decryptors](#partial-decryptors)
    * [Threshold decryption](#threshold-decryption)
  * [Pluggable backend](#pluggable-backend)
* [Security](#security)
* [Development](#development)

## Installation

```
npm install TODO
```

# Usage

## Preliminaries

### Cryptosystem setup

Vsslib operates over discrete-log based cryptosystems agnostically and you will need
to carry an instance of the respective backend in order to interact with the
library API.

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
Refer to Sec. [Pluggable backend](#pluggable-backend) for details.

### Secret generation

Generate a keypair in raw-bytes mode as follows.

```js
import { randomSecret } from "vsslib";

const { secret, publicBytes } = await randomSecret(ctx);
```

> **Note** 
> `secret` is the little-endian representation of a uniformly random scalar
modulo the underlying group order, while `publicBytes`
is the byte representation of the respective group element.

#### Extraction of public counterpart

```js
import { extractPublic } from "vsslib";

const publicBytes = await extractPublic(ctx, secret);
```

> **Warning**
> Throws error if `secret` is not a valid scalar representation
with respect to `ctx`.

## <a name="shamir-secret-sharing"></a>Shamir's secret sharing (SSS)

### Distributing the secret

Generate a (n, t)-sharing of a given secret as follows.

```js
import { shareSecret } from "vsslib";

const { sharing } = await shareSecret(ctx, n, t, secret);
```

> **Warning**
> Throws error if the condition `1<=t<=n<q` is not satisfied, where `q` stands
> for the underlying group's order, or if the provided secret is unvalid with
> respect to `ctx`.

If not provided, the secret is created on the fly and can be returned
along with the sharing.

```js
const { secret, sharing } = await shareSecret(ctx, n, t);
```

### Basic sharing interface

Access of original secret in raw-bytes mode:

```js
const secret = sharing.getOriginalSecret();
```

Access all secret shares in raw-bytes mode:

```js
const secretShares = await sharing.getSecretShares();
```

Access all public shares in raw-bytes mode:

```js
const publicShares = await sharing.getPublicShares();
```

Access the i-th share in raw-bytes mode:

```js
const { secretShare, publicShare } = await sharing.getShare(i);
```

Access the public counterpart of a secret share in raw-bytes mode:

```js
import { extractPublicShare } from "vsslib";

const publicShare = await extractPublicShare(ctx, secretShare);
```

> **Warning**
> Throws error if `secretShare.value` is not a valid scalar representation
with respect to `ctx`.

### Combination of secret shares

Combine any collection of secret shares using interpolation coefficients as
follows.

```js
import { combineSecretShares } from "vsslib";

const combinedSecret = await combineSecretShares(ctx, secretShares);
```

This yields the original secret only if the number of provided shares is at least equal
to threshold.
In order to ensure that the operation completes only if at least `t` shares are
provided, make sure to pass the threshold parameter explicitly.

```js
const combinedSecret = await combineSecretShares(ctx, secretShares, t);
```

> **Warning**
> Throws error if less than `t` shares are provided.

### Combination of public shares

Combine any collection of public shares using interpolation in the exponent as
follows.

```js
import { combinePublicShares } from "vsslib";

const combinedPublic = await combinePublicShares(ctx, publicShares);
```

> **Warning**
> This does not verify the shares during the combination process in any sense.
Refer to section [Verifiable public recovery](#verifiable-public-recovery)
for an operation that includes verification of public shares.

This yields the public counterpart of the original secret only if
the number of provided shares is at least equal to threshold.
In order to ensure that the operation completes only if at least `t` shares are
provided, make sure to pass the threshold parameter explicitly.

```js
const combinedPublic = await combinePublicShares(ctx, publicShares, t);
```

> **Warning**
> Throws error if less than `t` shares are provided.

## <a name="verifiable-secret-sharing"></a>Verifiable secret sharing (VSS)

In practice, shareholders need to defend
against malicious dealers and verify the consistency of their
shares, i.e., ensure that they have indeed occured from the same sharing.
This is attained by means of additional information used to verify
individual shares against some public quantity related to the sharing process.
Verifiable secret sharing (VSS) schemes extend Shamir's sharing by attaching
this information to the distributed shares.

Vsslib provides implementations of the
[Feldman](#feldman-scheme-1) and [Pedersen](#pedersen-scheme-1) VSS schemes,
which are the most widely used in practice. Verifiable packets
are directly extracted from the secret sharing instance.

> **Warning**
> Correctly applying VSS when implementing DKG protocols is out of the library's scope.
It is the user's responsibility to handle verification errors 
in order to adhere to the prescribed complaint policy and ensure that only
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
> Commitments are intended for broadcast while packets
> are sent to the respective shareholders by the dealer in private.

#### Verification and extraction of secret share

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
    // Handle verification failure
    ...
  } else {
    ... 
  }
}
```

### <a name="pedersen-scheme-1"></a>Pedersen scheme

Involved parties agree first on some public reference:

```js
import { randomPublic } from 'vsslib';

const publicBytes = await randomPublic(ctx);
```

#### Generation of Pedersen commitments and packets

Given a sharing, generate Pedersen commitments and verifiable packets for the totality of secret
shares as follows.

```js
const { packets, commitments } = await sharing.createPedersenPackets(publicBytes);
```

> **Note**
> Commitments are intended for broadcast while packets
> are sent to the respective shareholders by the dealer in private.

#### Verification and extraction of secret share

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
    // Handle verification failure
    ...
  } else {
    ... 
  }
}
```

## Verifiable public recovery

When reconstructing the public counterpart of a distributed secret, the
combiner usually needs to verify the aggregated public shares. Specifically, acclaimed
shareholders may be expected to prove knowledge of their respective secret shares
in a zero-knowledge (ZK) fashion.

> **Warning**
> This operation does not verify per se the consistency of the public shares.
> Specifically, it does not ensure that they combine to the public counterpart
> of a secret that has indeed been distributed.

> **Note**
> Refer to Sec [Combination of public shares](#combination-of-public-shares) for an
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

It can do so by storing a cryptographically secure nonce per session and
shareholder.
Upon receiving its respective nonce through some secure channel, the
shareholder includes it in packet generation as follows.

```js
const packet = await createSchnorrPacket(ctx, share, { ..., nonce });
```

### Recovery operation

After aggregating the packets, recover the combined public as follows.

```js
import { recoverPublic } from "vsslib";

const { recovered } = await recoverPublic(ctx, packets, { algorithm: "sha256", threshold: t });
```

This verifies the attached Schnorr proofs against the respective public
shares and combines the latter applying interpolation in the exponent.
The optional `algorithm` parameter specifies
the hash function used for the verification of individual
proofs (defaults to SHA256).
The operation throws `InvalidPublicShare` upon the first proof that fails to verify.
The optional `threshold` parameter ensures that the operation completes only if
at least `t` packets are provided, otherwise it throws `InvalidInput` error.

You will usually have to handle error in order to adhere to some specified rejection policy:

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

This can be done as follows, where the `index` field stands for the respective
shareholder's index.

```js
try {
  const { recovered } = await recoverPublic(ctx, packets, {
    ...,
    nonces: [
      { nonce: ..., index: 1 },
      { nonce: ..., index: 2 },
      ...
    ]
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

### Recovery with accurate blaming

For security investigation purposes, the combiner may want to trace potentially
cheating shareholders. This presupposes that the recovery operation completes
irrespective of potential verification failures and malicious shareholders are listed
in a blame index.

Disable early abort as follows:

```js
const { recovered, blame } = await recoverPublic(ctx, packets, { ..., errorOnInvalid: false });

if (blame.length > 0) {
  // Hold cheating shareholders accountable according to specified policy
  ...
}
```

This returns the combination result along with a (potentially empty) list `blame`,
containing the public shares of cheating shareholders.

> **Warning**
> Make sure to always check the `blame` index when using the `errorOnInvalid: false` option.

## Key layer

```js
import { shareKey } from "vsslib";

const sharing = await shareKey(privateKey, n, t); // (n, t)-Shamir sharing
```

### Share extraction

### Partial decryptors

#### <a name="partial-decryptor-generation"></a>Partial decryptor generation

#### <a name="decryptor-recovery"></a>Decryptor recovery

#### <a name="recovery-accurate-blaming"></a>Recovery with accurate blaming

#### <a name="raw-combination-of-partial-decryptors"></a>Raw combination of partial decryptors

### Threshold decryption

```js
const { ciphertext } = await publicKey.encrypt(message, { scheme: "ies" });
```

```js
const partialDrecryptor = await privateShare.computePartialDecryptor(ciphertext);
```

```js
const { plaintext } = await thresholdDecrypt(ctx, ciphertext, partialDrecryptors, partialPublics, { scheme });
```

#### Accurate blaming

```js
const { plaintext, blame } = await thresholdDecrypt(ctx, ciphertext, partialDrecryptor, partialPublics, { scheme, errorOnInvalid: false });
```

## Pluggable backend

# <a name="security-main"></a>Security

:warning: **This library requires security audit. Use at your own risk for the moment.**

#### <a name="input-validation-overview"></a>Input validation

TODO

#### <a name="nizk-overview"></a>Support for NIZK proofs

Threshold-cryptographic security against malicious shareholders
is attained by means of non-interactive zero-knowledge (NIZK) proofs
(e.g., decoupled Chaum-Pederesen protocols in a threshold decryption scheme).

Vsslib provides NIZK infrastructure ([`vsslib/nizk`](./src/nizk.ts))
for proving knowledge of generic discrete-log based linear relations
over arbitrary groups and hash
functions. It takes care to avoid the
weak Fiat-Shamir transform [pitfall](https://eprint.iacr.org/2016/771.pdf)
by default.

It is the user's responsibility to properly utilize NIZKs when implementing
a protocol from scratch.

#### <a name="replay-attacks-overview"></a>Defence against replay attacks

In practice, plain usage of NIZK proofs is usually susceptible to replay
attack.
The combiner may need to defend against it by maintaining some kind
of state between itself and individual shareholders.

Vsslib allows inclusion of nonces when generating a NIZK proof, which must in
turn be included when verifying proofs from the combiner's side.
A nonce can be any bytestring capable of mutually maintaining state,
e.g. cryptographically secure random bytes, unique session identifiers,
synchronized counters, or combinations thereof.
It is the user's responsibility to ensure that its design is secure in the
particular application context.

#### <a name="constant-time-comparisons-validation-overview"></a>Constant-time comparisons

TODO

#### <a name="knwon-weakeness-overview"></a>Known weaknesses

TODO

# Development

## Installation

```
$ npm install
```

### Watch

```
$ npm run dev
```

### Build

```
$ npm run build
```

### Lint

```
$ npm run lint
```

### Examples

```
npx tsx examples/<file> run
```

```
npx tsx examples/<file> --help
```

## Tests

```
$ ./test.sh --help
```

```
$ npm run test[:reload]
```

## Benchmarks

```
$ ts-node bench/sample.ts
```

## Documentation

```
$ npm run docs
```
