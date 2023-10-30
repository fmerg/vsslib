# vsslib

**Interfaces for Verifiable Secret Sharing**

## Install

## Usage

### Key generation

```js
import { Key } from 'vsslib';

const key = await Key.generate({ crypto: 'ed25519' });
const pub = await key.extractPublic();
```


### Key serialization

```js
const serialized = await key.serialize();
```

The original key is recovered as follows:

```js
const keyBack = await Key.deserialize(serialized, { crypto: 'ed25519' });
const areEqual = await keyBack.isEqual(key);  // true;
```

The public counterpart is serialized in a similar fashion:

```js
const serialized = await pub.serialize();
```

It can be recovered as follows:

```js
import { Public } from 'vsslib';

const pubBack = await Public.deserialize(serialized, { crypto: 'ed25519' });
const areEqual = await pubBack.isEqual(pub);  // true
```

## Modules

- [`vsslib.backend`](./src/backend)
- [`vsslib.key`](./src/key)
- [`vsslib.sigma`](./src/sigma)
- [`vsslib.elgamal`](./src/elgamal)
- [`vsslib.lagrange`](./src/lagrange)
- [`vsslib.shamir`](./src/shamir)
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
