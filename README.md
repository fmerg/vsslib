# vsslib

**Interfaces for Verifiable Secret Sharing**

## Install

## Usage

```js
import { key } from 'vsslib';

const { privateKey, PublicKey } = key.generate('ed25519');
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
