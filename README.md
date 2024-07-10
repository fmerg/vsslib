# vsslib

Primitives for Verifiable Secret Sharing (VSS) and Threshold Cryptography
in TS/JS

:warning: **This library requires security audit. Use at you own risk for
the moment.**

## Quick example

**Crypto setup**
```js
import { initBackend } from "vsslib";

const ctx = initBackend("ed25519");
```

**Dealer's side**
```js
import { distributeSecret, extractPublic, createFeldmanPackets } from "vsslib";

// Generate Shamir (5, 3)-sharing for some random secret
const { secret, sharing } = await distributeSecret(ctx, 5, 3);

// Extract public counterpart if needed
const publicBytes = await extractPublic(ctx, secret);

// Generate verifiable packets for the totality of secret shares
const { packets, commitments } = await sharing.createFeldmanPackets();

// Send packets to respective shareholders and broadcast commitments
```

**Shareholder's side**
```js
import { parseFeldmanPacket, extractPublicShare } from "vsslib";

// Extract and verify secret share from received packet
const secretShare = await parseFeldmanPacket(ctx, commitments, packet);

// Infer public counterpart if needed
const publicShare = await extractPublicShare(ctx, secretShare);
```

**Combiner's side**

```js
import { combinePublicShares } from "vsslib";

// Recover `publicBytes` from a qualified collection of public shares
const combinedPublic = await combinePublicShares(ctx, publicShares.slice(0, 3));
```

## Table of contents

* [Installation](#installation)
* [Overview](#overview)
  * [Backend](#backend-overview)
  * [Interface](#interface-overview)
  * [Security](#security-overview)
* [Usage](#usage)
  * [Preliminaries](#preliminaries)
    * [Cryptosystem setup](#cryptosystem-setup)
    * [Secret generation](#secret-generation)
  * [Shamir's secret sharing (SSS)](#shamir-secret-sharing)
    * [Distribution of secret](#distribution-of-secret)
    * [Combination of secret shares](#combination-of-secret-shares)
    * [Raw combination of public shares](#raw-combination-of-public-shares)
  * [Verifiable secret sharing (VSS)](#verifiable-secret-sharing)
    * [Feldman scheme](#feldman-scheme-1)
    * [Pedersen scheme](#pedersen-scheme-1)
  * [Verifiable public recovery](#verifiable-public-recovery)
    * [Verifiable share packets](#verifiable-share-packets)
    * [Recovery operation](#recovery-operation)
    * [Recovery with accurate blaming](#recovery-with-accurate-blaming)
  * [Key sharing](#key-sharing)
    * [Feldman VSS scheme](#TODO)
    * [Pedersen VSS scheme](#TODO)
    * [Public key recovery](#public-key-recovery)
  * [Threshold decryption](#threshold-decryption)
    * [Accurate blaming](#accurate-blaming)
* [Pluggable backend](#pluggable-backend)
* [Security](#security)
* [Development](#development)

## Installation

```
npm install TODO
```

## Overview

Vsslib provides modular building blocks for implementing threshold-cryptographic protocols
based on Shamir's Secret Sharing. It focuses on primitives that make the
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

Vsslib exposes two separate APIs. The ["raw bytes"](#shamir-secret-sharing) interface is intended
for applications where more freedom is required on how
to directly access and use secrets
(e.g., distributed generation of ephemeral secrets, or under the constraints imposed
by a pre-existing public-key interface).
The ["keys"](#key-sharing) interface is a public-key API that provides asymmetric operations
at the high-level and is compatible with
ready-made solutions for verifiable key recovery and
[threshold decryption](#threshold-decryption).
Both operate with the same sharing abstraction layer.

### <a name="security-overview"></a>Security

:warning: **This library requires security audit. Use at your own risk for the moment.**

#### <a name="input-validation-overview"></a>Input validation

#### <a name="constant-time-comparisons-validation-overview"></a>Constant-time comparisons

#### <a name="replay-attacks-overview"></a>Defence against replay attacks

#### <a name="knwon-weakeness-overview"></a>Known weaknesses

#### <a name="selection-of-parameters-overview"></a>Remark on the selection of parameters

Vsslib is unopinionated on the selection of cryptographic parameters
(underlying cryptosystem, hash function for ZK-proofs,
encryption scheme, etc.), allowing complete freedom on how to
orthogonally combine them.

For example, the provided threshold decryption mechanism is operable with
plain Elgamal encryption even if this combination is per se insecure
against chosen-ciphertext attacks.
It is the user's responsibility to decide if the desired level of security
is attained in a particular context by other means.

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
> You can use any custom or other implementation in place of `initBackend`,
provided that it conforms to or has been wrapped with the internally
prescribed interface.
Refer to Sec. [Pluggable backend](#pluggable-backend) for details.

### Secret generation

Generate a keypair in raw-bytes mode as follows.

```js
import { generateSecret } from "vsslib";

const { secret, publicBytes } = await generateSecret(ctx);
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

### Distribution of secret

Generate a (n, t)-sharing of a given secret as follows.

```js
import { distributeSecret } from "vsslib";

const { sharing } = await distributeSecret(ctx, n, t, secret);
```

> **Warning**
> Throws error if the condition `1<=t<=n<q` is not satisfied, where `q` stands
> for the underlying group's order, or if the provided secret is unvalid with
> respect to `ctx`.

If not provided, the secret is created on the fly and can be returned
along with the sharing.

```js
const { secret, sharing } = await distributeSecret(ctx, n, t);
```

### Share extraction

Access the original secret in raw-bytes mode as follows.

```js
const secret = sharing.getOriginalSecret();
```

Access the totality of secret shares in raw-bytes mode as follows.

```js
const secretShares = await sharing.getSecretShares();
```

Access the totality of public shares in raw-bytes mode as follows.

```js
const publicShares = await sharing.getPublicShares();
```

Access the i-th share in raw-bytes mode as follows.

```js
const { secretShare, publicShare } = await sharing.getShare(i);
```

Access the public counterpart of a secret share in raw-bytes mode as follows.

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

### Raw combination of public shares

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

In most distributed protocols, shareholders need to defend
against malicious dealers and verify the consistency of their
shares (i.e., ensure that these combine indeed to some reconstructible secret).
This is attained by means of additional information used to verify
individual shares against some public quantity related to the sharing process.
Verifiable secret sharing (VSS) schemes extend Shamir's sharing by including
this information to the secret packets sent to the shareholders.

Vsslib provides implementations of the
[Feldman](#feldman-scheme-1) and [Pedersen](#pedersen-scheme-1) VSS schemes,
which are the most widely used in practice. Verifiable packets
are directly extracted from the sharing instance.

> **Warning**
> Correctly applying VSS when implementing DKG protocols is out of the library's scope.
It is the user's responsibility to handle verification errors 
in order to adhere to the prescribed complaint policy and ensure that only
non-byzantine parties end up with a share.

### <a name="feldman-scheme-1"></a>Feldman scheme

Generate Feldman commitments and verifiable packets for the totality of secret
shares as follows.

```js
const { packets, commitments } = await sharing.createFeldmanPackets();
```

Extract and verify secret share from the received packet as follows.

```js
import { parseFeldmanPacket } from "vsslib";

const share = await parseFeldmanPacket(ctx, commitments, packet);
```

> **Warning**
> Throws error if the included share is found invalid
against the provided commitments.

#### Standalone verification of secret share

A share can be directly verified against the broadcast commitments as
follows.

```js
import { verifyFeldmanCommitments } from "vsslib";

await verifyFeldmanCommitments(ctx, share, commitments);
```

### <a name="pedersen-scheme-1"></a>Pedersen scheme

Involved parties agree first on some public reference:

```js
const publicBytes = await ctx.randomPublic();
```

Generate Pedersen commitments and verifiable packets for the totality of secret
shares as follows.

```js
const { packets, commitments } = await sharing.createPedersenPackets(publicBytes);
```

Extract and verify secret share from the received packet as follows.

```js
import { parsePedersenPacket } from "vsslib";

const { share, binding } = await parsePedersenPacket(ctx, commitments, publicBytes, packet);
```

> **Warning**
> Throws error if the included share is found invalid
against the provided commitments and public reference.

The included secret `binding` is implicitly used during verification and can be
discarded.

#### Standalone verification of secret share

A share can be directly verified against the broadcast commitments
and public referece using the included binding.

```js
import { verifyPedersenCommitments } from "vsslib";

await verifyPedersenCommitments(ctx, share, binding, publicBytes, commitments);
```

## Verifiable public recovery

When reconstructing the public counterpart of a distributed secret, the
combiner usually needs to verify the aggregated public shares. Specifically, acclaimed
shareholders are expected to prove knowledge of their respective secret shares
in a zero-knowledge (ZK) fashion.

> **Note**
> Refer to section [Raw combination](#raw-combination-of-public-shares) for an
> operation that bypasses verification of public shares.

### Verifiable share packets

Create a verifiable packet for a secret share as follows.

```js
import { createScnorrPacket } from "vsslib";

const packet = await createScnorrPacket(ctx, share, { algorithm: "sha256" });
```

This consists of the public share and a NIZK (Schnorr) proof-of-knowledge of
the secret counterart.
The optional `algorithm` parameter specifies the hash function used for proof
generation (defaults to SHA256).

>  **Note**
> Involved shareholders are expected to use the same hash function.

### Recovery operation

After aggregating the packets, recover the combined public as follows.

```js
import { recoverPublic } from "vsslib";

const { recovered } = await recoverPublic(ctx, packets, { algorithm: "sha256", threshold: t });
```

This verifies the attached Schnorr proofs against the respective public
shares and combines the latter applying interpolation in the exponent.
It throws `InvalidPublicShare` if at least one of the included proofs fails to verify.
The optional `threshold` parameter ensures that the operation completes only if
at least `t` packets are provided.
The optional `algorithm` parameter specifies
the hash function used by the combiner for the verification of individual
proofs (defaults to SHA256).

### Recovery with accurate blaming

For security investigation purposes, the combiner may want to trace potentially
cheating shareholders. This presupposes that the recovery operation completes
irrespective of potential verification failures and malicious shareholders are listed
in a blame index.

```js
const { recovered, blame } = await recoverPublic(ctx, packets, {
  algorithm: "sha256", threshold: t, errorOnInvalid: false
});
```

## Key sharing

```js
const { privateKey } = await generateKey(ctx);

const sharing = await privateKey.generateSharing(5, 3);
```

### Feldman VSS scheme

```js
const { packets, commitments } = await sharing.createFeldmanPackets();
```

```js
import { extractPartialKey } from "vsslib";

const privateShare = await extractPartialKey(ctx, commitments, packet);
```

### Pedersen VSS scheme

```js
const { packets, commitments } = await sharing.createPedersenPackets(publicBytes);
```

```js
import { extractPartialKey } from "vsslib";

const privateShare = await extractPartialKey(ctx, commitments, packet);
```

### Public key recovery

```js
import { recoverPublicKey } from "vsslib";
```

```js
const { publicKey } = await recoverPublicKey(ctx, publicKeyShares, { algorithm });
```

#### Recovery with accurate blaming

```js
const { publicKey, blame } = await recoverPublicKey(ctx, publicKeyShares, { algorithm, errorOnInvalid: false });
```

## Threshold decryption

```js
const { ciphertext } = await publicKey.encrypt(message, { scheme: "ies" });
```

```js
const partialDrecryptor = await privateShare.computePartialDecryptor(ciphertext);
```

```js
const { plaintext } = await thresholdDecrypt(ctx, ciphertext, partialDrecryptors, partialPublics, { scheme });
```

### Accurate blaming

```js
const { plaintext, blame } = await thresholdDecrypt(ctx, ciphertext, partialDrecryptor, partialPublics, { scheme, errorOnInvalid: false });
```

## Pluggable backend

# Security

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

## Documentation

```
$ npm run docs
```
