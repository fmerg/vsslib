# vsslib

**Interfaces for Verifiable Secret Sharing**

## Install

## Usage

```js
import { initGroup } from "vsslib";

const ctx = initGroup("ed25519");
```

### Verifiable Secret Sharing

```js
import { distributeSecret } from "vsslib";

const sharing = await distributeSecret(ctx, 5, 3, secret);
```

#### Feldman VSS scheme

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

#### Pedersen VSS scheme

```js
const { packets, commitments } = await sharing.createFeldmanPackets();
```

```js
import { parsePedersenPacket } from "vsslib";

const { share, binding } = await parsePedersenPacket(
  ctx, commitments, publicBytes, packet
);
```

```js
import { verifyPedersenCommitments } from "vsslib";

await verifyPedersenCommitments(
  ctx, share, bindng, publicBytes, commitments
);
```

#### Reconsctruction

```js
import { reconstructPublic } from "vsslib";

const globalPublic = await reconstructPublic(ctx, publicShares);
```

### Verifiable Key Distribution

```js
import { generateKey } from "vsslib";

const { ctx, privateKey } = await generateKey("ed25519");
```

```js
const sharing = await privateKey.generateSharing(5, 3);
```

#### Feldman scheme

```js
const { packets, commitments } = await sharing.createFeldmanPackets();
```

```js
import { PrivateKeyShare } from "vsslib";

const privateShare = await PrivateKeyShare.fromFeldmanPacket(ctx, commitments, packet);
```

#### Pedersen scheme

```js
const { packets, commitments } = await sharing.createPedersenPackets(publicBytes);
```

```js
import { PrivateKeyShare } from "vsslib";

const privateShare = await PrivateKeyShare.fromPedersenCommitments(
  ctx, commitments, publicBytes, packet
);
```

#### Public key reconstruction

```js
import { reconstructPublicKey } from "vsslib";

const globalPublicKey = await reconstructPublicKey(ctx, publicKeyShares, threshold);
```

### Threshold decryption

```js
const { ciphertext } = await publicKey.encrypt(message, { scheme: "ies" });
```

```js
const partialDecryptor = await privateShare.computePartialDecryptor(ciphertext);
```

```js
await publicShare.verifyPartialDecryptor(ciphertext, partialDecryptor);
```

```js
import { verifyPartialDecryptors } from "vsslib";

const { flag, indexes } = await verifyPartialDecryptors(
  ctx, ciphertext, publicShares, partialDecryptors
);
```

```js
await verifyPartialDecryptors(
  ctx, ciphertext, publicShares, partialDecryptors, { raiseOnInvalid: True }
);
```

```js
const plaintext = await thresholdDecrypt(ciphertext, partialDecryptors);
```

### Threshold authentication


## Modules

- [`vsslib.arith`](./src/arith)
- [`vsslib.backend`](./src/backend)
- [`vsslib.crypto`](./src/crypto)
- [`vsslib.elgamal`](./src/elgamal)
- [`vsslib.keys`](./src/keys)
- [`vsslib.nizk`](./src/nizk)
- [`vsslib.polynomials`](./src/polynomials)
- [`vsslib.signer`](./src/signer)

## Development

```
$ npm install
```

### Watch

```
$ npm run dev
```

### Tests

```
$ ./test.sh --help
```

```
$ npm run test[:reload]
```

## Build

```
$ npm run build
```

## Command line

```
$ npm run vss [command] -- [options]
```

## Documentation

```
$ npm run docs
```
