# vsslib

**Interfaces for Verifiable Secret Sharing**

## Install

## Usage

```js
import { key } from 'vsslib';

const { privateKey, publicKey, ctx } = await key.generate('ed25519');
```

```js
import { core } from 'vsslib';

const combiner = await core.initCombiner({ label: 'ed25519', threshold: 3 })
```

### Key sharing

```js
const sharing = privateKey.distribute(5, 3);

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

## Modules

- [`vsslib.aes`](./src/aes)
- [`vsslib.elgamal`](./src/elgamal)
- [`vsslib.backend`](./src/backend)
- [`vsslib.core`](./src/core)
- [`vsslib.plain`](./src/elgamal)
- [`vsslib.ies`](./src/elgamal)
- [`vsslib.kem`](./src/elgamal)
- [`vsslib.key`](./src/key)
- [`vsslib.polynomials`](./src/polynomials)
- [`vsslib.schnorr`](./src/schnorr)
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
