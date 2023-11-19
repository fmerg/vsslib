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

const combiner = await core.initCombiner({ label: 'ed25519', threshold: 3 })
```

### Key distribution

```js
const distribution = privateKey.distribute(5, 3);

const publicShares = await distribution.getPublicShares();
```

### Threshold decryption

```js
const message = await publicKey.ctx.randomPoint();

const { ciphertext } = await publicKey.elgamalEncrypt(message);
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
const plaintext = await combiner.elgamalDecrypt(ciphertext, partialDecryptors);
```

## Modules

- [`vsslib.aes`](./src/aes)
- [`vsslib.asymmetric`](./src/asymmetric)
- [`vsslib.backend`](./src/backend)
- [`vsslib.core`](./src/core)
- [`vsslib.elgamal`](./src/asymmetric)
- [`vsslib.ies`](./src/asymmetric)
- [`vsslib.kem`](./src/asymmetric)
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
