# vsslib

**Primitives for Verifiable Secret Sharing (VSS) and Threshold Cryptography
in Typescript**

*This library is currently a prototype and requires security audit. Use at your own risk for the moment.*

## Quick example

```js
import { initBackend, parseFeldmanPacket, combineSecretShares } from "vsslib";

const ctx = initBackend("ed25519");


import { generateSecret, distributeSecret } from "vsslib";

const { secret } = await genrerateSecret(ctx);
const { sharing } = await distributeSecret(ctx, 5, 3, secret);

const { packets, commitments } = await sharing.createFeldmanPackets();

const secretShares = [];
for (const packet of packets) {
  const share = await parseFeldmanPacket(ctx, commitments, packet);
}

import { combinedSecret } from "vsslib";

const combinedSecret = await combineSecretShares(ctx, secretShares.slice(0, 3));
```

## Overview

Vsslib provides building blocks for implementing threshold-cryptographic protocols
based on Shamir's Secret Sharing (SSS). It focuses on primitives that make the
sharing process verifiable on behalf of involved parties
(Feldman and Pedersen VSS) and as such applicable in contexts
with zero or low trust assumptions (e.g., Distributed Key Generation (DKG) protocols).

### Pluggable backend

Vsslib has been designed to be agnostic with respect to the underlying cryptosystem
and to admit pluggable backends (provided that these conform to an internal abstract
interface).

### Interface architecture

Vsslib exposes two separate APIs. The "raw bytes" interface is suited
for implementations where more fine-grained control is required on how
to access and use secrets at a lower level
(e.g., distributed generation of combined secrets under special assumptions).
The "keys" interface is a public-key API that provides asymmetric operations
at the high-level ([`vsslib.keys`](./src/keys)) and is compatible
with ready-made solutions for combined key recovery and threshold decryption.
Both interfaces operate with the same VSS abstraction layer.

### Security 

#### Remark on the selection of parameters

Vsslib is unopinionated on the selection of cryptographic parameters
(elliptic curve, hash function for zero-knowledge proofs,
encryption scheme, etc.), allowing complete freedom on how to
orthogonally combine them.
For example, the provided threshold decryption mechanism is operable with
plain Elgamal encryption even if this combination is insecure
against chosen-ciphertext attacks.
It is the user's responsibility to decide if a per se insecure selection
of parameters attains the desired level of security
in a particular context by other means.

## Table of contents

* [Installation](#installation)
* [Usage](#usage)
  * [Preliminaries](#preliminaries)
    * [Cryptosystem initialization](#cryptosystem-initialization)
    * [Secret generation](#secret-generation)
  * [Shamir's secret sharing (SSS)](#shamir-secret-sharing)
    * [Distribution of secret](#TODO)
    * [Combination of shares](#TODO)
  * [Verifiable secret sharing (VSS)](#verifiable-secret-sharing)
    * [Feldman scheme](#feldman-scheme-1)
    * [Pedersen scheme](#pedersen-scheme-1)
  * [Verifiable public recovery](#TODO)
  * [Key sharing](#key-sharing)
    * [Feldman VSS scheme](#TODO)
    * [Pedersen VSS scheme](#TODO)
    * [Public key recovery](#pbulic-key-recovery)
  * [Threshold decryption](#threshold-decryption)
    * [Standard usage](#standard-usage)
    * [Standalone decryptor recovery](#standlone-decryptor-recovery)
    * [Raw combination of partial decryptors](#raw-combination-of-partial-decryptors)
* [Pluggable backend](#pluggable-backend)
* [Security](#security)
* [Development](#development)

## Installation

```
npm install TODO
```

# Usage

## Preliminaries

Secret sharing is abstractly defined over discrete-log (DL) based cryptosystems,
suitable for doing standard asymmetric cryptography (e.g., elliptic curves).
Vsslib operates on top of such cryptosystems agnostically.

### Cryptosystem initialization

You will need to carry an instance of the underlying cryptosystem
in order to interact with the library API. This can be initialized as follows.

```js
import { initBackend } from "vsslib";

const ctx = initBackend("ed25519");
  ```

The currently supported cryptosystems are  `ed25519`, `ed448` and `jubjub`.

### Secret generation

```js
import { generateSecret } from "vsslib";

const { secret, publicBytes } = await generateSecret(ctx);
```

```js
import { extractPublic } from "vsslib";

const publicBytes = await extractPublic(ctx, secret);
```

## <a name="shamir-secret-sharing"></a>Shamir's secret sharing (SSS)

### Distribution of secret

```js
import { distributeSecret } from "vsslib";

const { secret, sharing } = await distributeSecret(ctx, 5, 3);
```

### Combination of shares

```js
import { combineSecretShares } from 'vsslib';

const combinedSecret = await combineSecretShares(ctx, shares, { threshold });
```

```js
import { combinePublicShares } from 'vsslib';

const combinedPublic = await combinePublicShares(ctx, shares, { threshold });
```

## <a name="verifiable-secret-sharing"></a>Verifiable secret sharing (VSS)

### <a name="feldman-scheme-1"></a>Feldman scheme

```js
const { packets, commitments } = await sharing.createFeldmanPackets();
```

```js
import { parseFeldmanPacket } from "vsslib";

const share = await parseFeldmanPacket(ctx, commitments, packet);
```

```js
import { verifyFeldmanCommitments } from "vsslib";

await verifyFeldmanCommitments(ctx, share, commitments);
```

### <a name="pedersen-scheme-1"></a>Pedersen scheme

```js
const { packets, commitments } = await sharing.createPedersenPackets(publicBytes);
```

```js
import { parsePedersenPacket } from "vsslib";

const { share, binding } = await parsePedersenPacket(ctx, commitments, publicBytes, packet);
```

```js
import { verifyPedersenCommitments } from "vsslib";

await verifyPedersenCommitments(ctx, share, bindng, publicBytes, commitments);
```

### Verifiable public recovery

```js
import { createPublicPacket } from 'vsslib';

const packet = await createPublicPacket(ctx, share, { algorithm, nonce });
```


```js
import { recoverPublic } from 'vsslib';

const { recovered } = await recoverPublic(ctx, packets, { algorithm });
```

```js
const { recovered, blame } = await recoverPublic(ctx, packets, { algorithm, errorOnInvalid: false});
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

```js
const { publicKey, blame } = await recoverPublicKey(ctx, publicKeyShares, { algorithm, errorOnInvalid: false });
```

## Threshold decryption

### Standard usage

```js
const { ciphertext } = await publicKey.encrypt(message, { scheme: "ies" });
```

```js
const partialDrecryptor = await privateShare.computePartialDecryptor(ciphertext);
```

```js
const { plaintext } = await thresholdDecrypt(ctx, ciphertext, partialDrecryptors, partialPublics, { scheme });
```

```js
const { plaintext, blame } = await thresholdDecrypt(ctx, ciphertext, partialDrecryptor, partialPublics, { scheme, errorOnInvalid: false });
```

### Standalone decryptor recovery

```js
import { recoverDecryptor } from "vsslib";

const { recovered } = await recoverDecryptor(ctx, shares, ciphertext, partialPublics);
```

```js
const { recovered, blame } = await recoverDecryptor(ctx, shares, ciphertext, partialPublics, { errorOnInvalid: false });
```

### Raw combination of partial decryptors


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
