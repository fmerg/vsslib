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

### Verification

## Feldmann commitments

```js
const { commitments } = await polynomial.proveFeldmann();
```

```js
const secret = await polynomial.evaluate(index);
```

```js
import { verifyFeldmann } from 'vsslib/vss';

const verified = await verifyFeldmann(ctx, secret, index, commitments);
```


## Pedersen commitments

```js
const hPub = await ctx.randomPoint();
const nr = 7;

const { commitments, bindings } = await polynomial.provePedersen(nr, hPub);
```

```js
const secret = await polynomial.evaluate(index);

const binding = bindings[index];
```

```js
import { verifyPedersen } from 'vsslib/vss';

const verified = await verifyPedersen(ctx, secret, binding, index, hPub, commitments);
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
