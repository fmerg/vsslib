# vsslib

**Interfaces for Verifiable Secret Sharing**

## Install

## Cryptosystem initialization

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
import { createPublicSharePacket } from 'vsslib';

const packet = await createPublicSharePacket(ctx, share, { algorithm, nonce });
```

### Secret recovery

```js
import { combineSecretShares } from 'vsslib';
```

```js
const result = await combineSecretShares(ctx, shares, { threshold });
```

### Public point recovery


```js
import { recoverPublic } from 'vsslib';
```

```js
const { result } = await recoverPublic(ctx, packets, { algorithm });
```

```js
const { result, blame } = await recoverPublic(ctx, packets, { algorithm, errorOnInvalid: false});
```

#### Raw combination of public shares

```js
import { combinePublicShares } from 'vsslib';
```

```js
const result = await combinePublicShares(ctx, shares, { threshold });
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
import { PrivateKeyShare } from "vsslib";

const privateShare = await PrivateKeyShare.fromFeldmanPacket(ctx, commitments, packet);
```

### Pedersen VSS scheme

```js
const { packets, commitments } = await sharing.createPedersenPackets(publicBytes);
```

```js
import { PrivateKeyShare } from "vsslib";

const privateShare = await PrivateKeyShare.fromPedersenCommitments(ctx, commitments, publicBytes, packet);
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

const { result } = await recoverDecryptor(ctx, shares, ciphertext, publicShares);
```

```js
const { result, blame } = await recoverDecryptor(ctx, shares, ciphertext, publicShares, { errorOnInvalid: false });
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
