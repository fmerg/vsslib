# vsslib

**Interfaces for Verifiable Secret Sharing (VSS)**

## Install

## Initialization

```js
import { initBackend } from "vsslib";

const ctx = initBackend("ed25519");
```

## Verifiable secret sharing

### Shamir sharing

```js
import { distributeSecret } from "vsslib";

const secret = await ctx.randomSecret();

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

#### Verifiable public shares

```js
import { createPublicPacket } from 'vsslib';

const packet = await createPublicPacket(ctx, share, { algorithm, nonce });
```

### Secret recovery

```js
import { combineSecretShares } from 'vsslib';
```

```js
const combinedSecret = await combineSecretShares(ctx, shares, { threshold });
```

### Public recovery


```js
import { recoverPublic } from 'vsslib';
```

```js
const { recovered } = await recoverPublic(ctx, packets, { algorithm });
```

```js
const { recovered, blame } = await recoverPublic(ctx, packets, { algorithm, errorOnInvalid: false});
```

#### Raw combination of public shares

```js
import { combinePublicShares } from 'vsslib';
```

```js
const combinedPublic = await combinePublicShares(ctx, shares, { threshold });
```

## Private key sharing

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

```js
const { ciphertext } = await publicKey.encrypt(message, { scheme: "ies" });
```

```js
const decryptorShare = await privateShare.computePartialDecryptor(ciphertext);
```

```js
const { plaintext } = await thresholdDecrypt(ctx, ciphertext, decryptorShares, publicShares, { scheme });
```

```js
const { plaintext, blame } = await thresholdDecrypt(ctx, ciphertext, decryptorShares, publicShares, { scheme, errorOnInvalid: false });
```

### Decryptor recovery

```js
import { recoverDecryptor } from "vsslib";

const { recovered } = await recoverDecryptor(ctx, shares, ciphertext, publicShares);
```

```js
const { recovered, blame } = await recoverDecryptor(ctx, shares, ciphertext, publicShares, { errorOnInvalid: false });
```


## Modules

- [`vsslib.keys`](./src/keys)


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
