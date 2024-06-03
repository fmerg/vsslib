# vsslib

**Interfaces for Verifiable Secret Sharing**

## Install

## Usage

```js
import { generateKey } from 'vsslib';

const { privateKey, publicKey, ctx } = await generateKey('ed25519');
```

### Sharing

```js
import { shareKey } from 'vsslib';

const sharing = shareKey(5, 3, privateKey);
```

```js
const { nrShares, threshold, polynomial } = sharing;
```

```js
const privateShares = await sharing.getPrivateShares();
```

```js
const publicShares = await sharing.getPublicShares();
```

### Verification


#### Feldmann VSS scheme

```js
// TODO
```

#### Pedersen VSS scheme

```js
const publicBytes = (await ctx.randomPoint()).toBytes();
```

```js
const { bindings, commitments } = await sharing.generatePedersenCommitments(publicBytes);
```

```js
const { bindings, commitments } = await sharing.generatePedersenCommitments(publicBytes);

const binding = bindings[privateShare.index];
```

```js
// TODO
```

### Reconstruction

```js
import { reconstructKey, reconstructPublic } from 'vsslib';
```

### Threshold decryption

```js
const { ciphertext } = await publicKey.encrypt(message, { scheme: 'ies' });
```

```js
const partialDecryptor = await privateShare.computePartialDecryptor(ciphertext);
```

```js
await publicShare.verifyPartialDecryptor(ciphertext, partialDecryptor);
```

```js
import { verifyPartialDecryptors } from 'vsslib';

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

## Modules

- [`vsslib.arith`](./src/arith)
- [`vsslib.backend`](./src/backend)
- [`vsslib.crypto`](./src/crypto)
- [`vsslib.elgamal`](./src/elgamal)
- [`vsslib.keys`](./src/keys)
- [`vsslib.lagrange`](./src/lagrange)
- [`vsslib.nizk`](./src/nizk)
- [`vsslib.shamir`](./src/shamir)
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
