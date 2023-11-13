# vsslib

**Interfaces for Verifiable Secret Sharing**

## Install

## Usage

```js
import { key } from 'vsslib';

const { privateKey, publicKey } = await key.generate('ed25519');
```

```js
import { core } from 'vsslib';

const combiner = await initCombiner({ label: 'ed25519', threshold: 3 })
```

### Key distribution

```js
const distribution = privateKey.distribute({ nrShares: 5, threshold: 3 });

const { threshold, privateShares, publicShares, polynomial, commitments } = distribution;

const publicShares = distribution.getPublicShares();
```

```js
const privateShare = privateShares[0];

await privateShare.verify(commitments);
```

### Key reconstruction

```js
const { privateKey, publicKey } = await combiner.reconstructKey(shares);
```

```js
const publicKey = await combiner.reconstructPublic(shares);
```

### Threshold decryption

```js
const { ciphertext } = await publicKey.encrypt(message);
```

```js
const partialDecryptor = await privateShare.generatePartialDecryptor(ciphertext);
```

```js
await publicShare.verifyPartialDecryptor(ciphertext, partialDecryptor);
```

```js
const { flag, indexes } = await combiner.verifyPartialDecryptors(
  ciphertext, publicShares, partialDecryptors
);
```

```js
const decryptor = await combiner.reconstructDecryptor(shares);
```

```js
const plaintext = await combiner.decrypt(ciphertext, shares);
```

## Modules

- [`vsslib.aes`](./src/aes)
- [`vsslib.backend`](./src/backend)
- [`vsslib.core`](./src/core)
- [`vsslib.elgamal`](./src/elgamal)
- [`vsslib.kem`](./src/kem)
- [`vsslib.key`](./src/key)
- [`vsslib.polynomials`](./src/polynomials)
- [`vsslib.shamir`](./src/shamir)
- [`vsslib.sigma`](./src/sigma)
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
