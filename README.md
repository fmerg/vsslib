# vsslib

**Interfaces for Verifiable Secret Sharing**

## Install

## Usage

```js
import { key } from 'vsslib';

const { privateKey, publicKey } = await key.generate('ed25519');
```

## Modules

- [`vsslib.backend`](./src/backend)
- [`vsslib.core`](./src/core)
- [`vsslib.elgamal`](./src/elgamal)
- [`vsslib.key`](./src/key)
- [`vsslib.lagrange`](./src/lagrange)
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
