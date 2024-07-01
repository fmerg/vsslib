
# vsslib

**Interfaces for Verifiable Secret Sharing (VSS)**

vsslib is a comprehensive library for implementing Verifiable Secret Sharing (VSS) schemes, providing robust cryptographic primitives for secure distributed systems.

## Table of Contents
- [Installation](#installation)
- [Initialization](#initialization)
- [Verifiable Secret Sharing](#verifiable-secret-sharing)
  - [Shamir Sharing](#shamir-sharing)
  - [Feldman VSS Scheme](#feldman-vss-scheme)
  - [Pedersen VSS Scheme](#pedersen-vss-scheme)
  - [Verifiable Public Shares](#verifiable-public-shares)
- [Secret Recovery](#secret-recovery)
- [Public Recovery](#public-recovery)
- [Private Key Sharing](#private-key-sharing)
- [Threshold Decryption](#threshold-decryption)
- [Modules](#modules)
- [Development](#development)
- [Build](#build)
- [Command Line Interface](#command-line-interface)
- [Documentation](#documentation)

## Installation

Install vsslib using npm:

```bash
npm install vsslib
```

## Initialization

Initialize the vsslib backend with the desired cryptographic curve:

```javascript
import { initBackend } from "vsslib";

const ctx = initBackend("ed25519");
```

## Verifiable Secret Sharing

Verifiable Secret Sharing (VSS) allows a secret to be split into multiple shares, which can be distributed among participants. The shares can later be combined to reconstruct the secret.

### Shamir Sharing

Shamir's Secret Sharing is a cryptographic algorithm to split a secret into multiple parts:

```javascript
import { distributeSecret } from "vsslib";

const secret = await ctx.randomSecret();
const sharing = await distributeSecret(ctx, 5, 3, secret);
```

### Feldman VSS Scheme

Feldman's VSS scheme adds verifiability to Shamir's Secret Sharing:

```javascript
// Create Feldman packets
const { packets, commitments } = await sharing.createFeldmanPackets();

// Parse Feldman packet
import { parseFeldmanPacket } from "vsslib";
const share = await parseFeldmanPacket(ctx, commitments, packet);

// Verify Feldman commitments
import { verifyFeldmanCommitments } from "vsslib";
await verifyFeldmanCommitments(ctx, share, commitments);
```

### Pedersen VSS Scheme

Pedersen's VSS scheme provides information-theoretic security:

```javascript
// Create Pedersen packets
const { packets, commitments } = await sharing.createPedersenPackets(publicBytes);

// Parse Pedersen packet
import { parsePedersenPacket } from "vsslib";
const { share, binding } = await parsePedersenPacket(ctx, commitments, publicBytes, packet);

// Verify Pedersen commitments
import { verifyPedersenCommitments } from "vsslib";
await verifyPedersenCommitments(ctx, share, binding, publicBytes, commitments);
```

### Verifiable Public Shares

Create verifiable public shares for transparent sharing:

```javascript
import { createPublicPacket } from 'vsslib';

const packet = await createPublicPacket(ctx, share, { algorithm, nonce });
```

## Secret Recovery

Combine secret shares to reconstruct the original secret:

```javascript
import { combineSecretShares } from 'vsslib';

const combinedSecret = await combineSecretShares(ctx, shares, { threshold });
```

## Public Recovery

Recover public information from shared packets:

```javascript
import { recoverPublic } from 'vsslib';

// Basic recovery
const { recovered } = await recoverPublic(ctx, packets, { algorithm });

// Recovery with error handling
const { recovered, blame } = await recoverPublic(ctx, packets, { algorithm, errorOnInvalid: false});

// Raw combination of public shares
import { combinePublicShares } from 'vsslib';
const combinedPublic = await combinePublicShares(ctx, shares, { threshold });
```

## Private Key Sharing

Share a private key among multiple parties:

```javascript
const { privateKey } = await generateKey(ctx);
const sharing = await privateKey.generateSharing(5, 3);

// Feldman VSS scheme
const { packets, commitments } = await sharing.createFeldmanPackets();

// Pedersen VSS scheme
const { packets, commitments } = await sharing.createPedersenPackets(publicBytes);

// Extract partial key
import { extractPartialKey } from "vsslib";
const privateShare = await extractPartialKey(ctx, commitments, packet);

// Public key recovery
import { recoverPublicKey } from "vsslib";
const { publicKey } = await recoverPublicKey(ctx, publicKeyShares, { algorithm });
const { publicKey, blame } = await recoverPublicKey(ctx, publicKeyShares, { algorithm, errorOnInvalid: false });
```

## Threshold Decryption

Perform threshold decryption using shared private keys:

```javascript
// Encrypt message
const { ciphertext } = await publicKey.encrypt(message, { scheme: "ies" });

// Compute partial decryptor
const decryptorShare = await privateShare.computePartialDecryptor(ciphertext);

// Threshold decryption
const { plaintext } = await thresholdDecrypt(ctx, ciphertext, decryptorShares, publicShares, { scheme });
const { plaintext, blame } = await thresholdDecrypt(ctx, ciphertext, decryptorShares, publicShares, { scheme, errorOnInvalid: false });

// Decryptor recovery
import { recoverDecryptor } from "vsslib";
const { recovered } = await recoverDecryptor(ctx, shares, ciphertext, publicShares);
const { recovered, blame } = await recoverDecryptor(ctx, shares, ciphertext, publicShares, { errorOnInvalid: false });
```

## Modules

Additional modules provided by vsslib:

- [`vsslib.keys`](./src/keys): Module for key management and operations.

## Development

Set up the development environment:

```bash
npm install
```

### Watch

Run the development server with hot-reloading:

```bash
npm run dev
```

### Tests

Run the test suite:

```bash
./test.sh --help
npm run test[:reload]
```

## Build

Build the project for production:

```bash
npm run build
```

## Command Line Interface

Use vsslib from the command line:

```bash
npm run vss [command] -- [options]
```

## Documentation

Generate documentation for the project:

```bash
npm run docs
```
