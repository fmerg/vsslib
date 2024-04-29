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
import { distributeKey } from 'vsslib';

const sharing = distributeKey(5, 3, privateKey);
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
const { commitments } = await sharing.proveFeldmann();
```

```js
import { verifyFeldmann } from 'vsslib';

await verifyFeldmann(ctx, privateShare, commitments);
```

#### Pedersen VSS scheme

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
import { verifyPedersen } from 'vsslib';

await verifyPedersen(ctx, share, binding, hPub, commitments);
```

### Reconstruction

```js
import { reconstructKey, reconstructPublic } from 'vsslib';
```


### Serialization

```js
import { serializePublicKey, deserializePublicKey } from 'vsslib/serializers';
```

```
import { serializePrivateShare, deserializePrivateShare } from 'vsslib/serializers';
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

- [`vsslib.backend`](./src/backend)
- [`vsslib.crypto`](./src/crypto)
- [`vsslib.keys`](./src/keys)
- [`vsslib.lagrange`](./src/lagrange)
- [`vsslib.nizk`](./src/nizk)
- [`vsslib.shamir`](./src/shamir)

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
