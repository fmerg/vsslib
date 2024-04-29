# vsslib

**Interfaces for Verifiable Secret Sharing**

## Install

## Usage

```js
import { generateKey } from 'vsslib';

const { privateKey, publicKey, ctx } = await generateKey('ed25519');
```

```js
import vss from 'vsslib/vss';

const ctx = initGroup(system);
const combiner = vss(ctx, threshold);
```

### Key sharing

```js
const sharing = vss.distributeKey(5, 3, privateKey);

const publicShares = await sharing.getPublicShares();
```

### Threshold decryption

```js
const { ciphertext } = await publicKey.encrypt(message, { scheme: 'ies' });
```

```js
const partialDecryptor = await privateShare.generatePartialDecryptor(ciphertext);
```

```js
await publicShare.verifyPartialDecryptor(ciphertext, partialDecryptor);
```

```js
const { flag, indexes } = await combiner.verifyPartialDecryptors(ciphertext, publicShares, partialDecryptors);
```

```js
const plaintext = await combiner.plainDecrypt(ciphertext, partialDecryptors);
```

## Verifiable identity (Schnorr identification scheme)

```js
const proof = await privateKey.proveIdentity({ algorithm: 'sha256'});
```

```js
await publicKey.verifyIdentity(proof);
```

## Verifiable key sharing (Shamir scheme)

```js
const sharing = vss.distributeKey(5, 3, privateKey);

const { nrShares, threshold, polynomial } = sharing;
```

```js
const privateShares = await sharing.getSecretShares();
```

```js
const publicShares = await sharing.getPublicShares();
```

### Feldmann verification scheme

```js
const { commitments } = await sharing.proveFeldmann();
```

```js
await verifyFeldmann(ctx, privateShare, commitments);
```

### Pedersen verification scheme

```js
const hPub = await ctx.randomPoint();
```

```js
const { bindings, commitments } = await sharing.provePedersen(hPub);
```

```js
const { bindings, commitments } = await sharing.provePedersen(hPub);
const binding = bindings[share.index];
```

```js
const verified = await verifyPedersen(ctx, share, binding, hPub, commitments);
```

### Verifiable partial decryptors

```js
const partialDecryptor = await privateShare.generatePartialDecryptor(ciphertext);
```

```js
await publicShare.verifyPartialDecryptor(ciphertext, partialDecryptor);
```


### Verification

## Feldmann commitments

## Pedersen commitments

## Modules

- [`vsslib.aes`](./src/aes)
- [`vsslib.elgamal`](./src/elgamal)
- [`vsslib.backend`](./src/backend)
- [`vsslib.core`](./src/core)
- [`vsslib.plain`](./src/elgamal)
- [`vsslib.ies`](./src/elgamal)
- [`vsslib.kem`](./src/elgamal)
- [`vsslib.key`](./src/key)
- [`vsslib.lagrange`](./src/lagrange)
- [`vsslib.enums`](./src/enums)
- [`vsslib.types`](./src/types)
- [`vsslib.schnorr`](./src/schnorr)
- [`vsslib.shamir`](./src/shamir)
- [`vsslib.nizk`](./src/nizk)
- [`vsslib.utils`](./src/utils)

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
