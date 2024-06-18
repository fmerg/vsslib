# vsslib

**Interfaces for Verifiable Secret Sharing**

## Install

## Usage

```js
import { initGroup } from "vsslib";

const ctx = initGroup("ed25519");
```

### Sharing

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

const { share, binding } = await parsePedersenPacket(ctx, commitments, publicBytes, packet);
```

```js
import { verifyPedersenCommitments } from "vsslib";

await verifyPedersenCommitments(ctx, share, bindng, publicBytes, commitments);
```

### Recovery


#### Secret scalar reconstruction

```js
import { recoverSecret } from 'vsslib';
```

```js
const result = await recoverSecret(shares);
```

#### Public point reconstruction

```js
import { recoverPublic } from 'vsslib';
```

```js
const { result } = await recoverPublic(ctx, packets, { algorithm });
```

```js
const { result, blame } = await recoverPublic(ctx, packets, { algorithm, errorOnInvalid: false});
```

#### Public point reconstruction without verification

```js
import { combiner } from 'vsslib';
```

```js
const result = await combinePublics(ctx, shares);
```

### Key Distribution

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

const privateShare = await PrivateKeyShare.fromPedersenCommitments(ctx, commitments, publicBytes, packet);
```

### Key recovery

```js
import { recoverKey } from "vsslib";

const recovered = await recoverKey(ctx, shares);
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

### Decryptor recovery

```js
import { recoverDecryptor } from "vsslib";

const { result } = await recoverDecryptor(ctx, shares, ciphertext, publicShares);
```

```js
const { result, blame } = await recoverDecryptor(ctx, shares, ciphertext, publicShares, { errorOnInvalid: false });
```

### Threshold decryption

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
