# vsslib

[![build status](https://img.shields.io/gitlab/pipeline-status/fmerg%2Fvsslib?branch=develop)](https://gitlab.com/fmerg/vsslib/-/pipelines?ref=develop)
[![npm version](https://img.shields.io/npm/v/vsslib.svg)](https://www.npmjs.com/package/vsslib)

Interfaces for Verifiable Secret Sharing (VSS) in TypeScript/JavaScript.

:warning: **This library requires a security audit. Use it at your own risk for
the moment.**

Vsslib provides building blocks for threshold-cryptographic protocols based on
Verifiable Secret Sharing (VSS), e.g. Distributed Key Generation (DKG) schemes
and threshold Schnorr signatures.

## Quick example

**Local setup**

The parties agree on a cryptosystem.

```js
import { initBackend } from "vsslib";

// Initiate cryptosystem instance over the ED25519 elliptic curve
const ctx = initBackend("ed25519");
```

**Dealer's side**
```js
import { shareSecret, createFeldmanPackets } from "vsslib";

// Generate a Shamir (5, 3)-sharing for some uniformly random secret
const { sharing } = await shareSecret(ctx, 5, 3);

// Generate verifiable packets for the totality of secret shares
const { packets, commitments } = await createFeldmanPackets(sharing);
```

Broadcast the commitments; send each packet privately to its shareholder.

**Shareholders' side**

```js
import { parseFeldmanPacket, InvalidSecretShare } from "vsslib";

// Extract and verify secret share from received packet
try {
  const { share } = await parseFeldmanPacket(ctx, commitments, packet, 3);
  // Store retrieved share locally
  ...
} catch (err) {
  if (err instanceof InvalidSecretShare) {
    // Follow rejection policy as specified by context
    ...
  } else {
    ...
  }
}
```

See [`examples`](./examples/dkg.ts) for complete flows of SSS, VSS, DKG and
threshold Schnorr signatures.

## Overview

On top of [Shamir's Secret Sharing](./USAGE.md#shamirs-secret-sharing-sss)
(SSS), vsslib makes the sharing verifiable by the parties
([Feldman](./USAGE.md#feldman-scheme) and
[Pedersen](./USAGE.md#pedersen-scheme) VSS), for settings with zero or low
trust, and the public key of the secret
[recoverable](./USAGE.md#verifiable-public-key-recovery).

See also [USAGE.md](./USAGE.md), [SECURITY.md](./SECURITY.md) and
[PERFORMANCE.md](./PERFORMANCE.md).

### Backend

Vsslib is agnostic of the underlying cryptosystem: it interacts only with a
generic group interface, so backends are pluggable. It comes with several
backends based on [`noble-curves`](https://github.com/paulmillr/noble-curves),
but any implementation wrapped with the prescribed interface should do the job,
provided that it operates over a group of prime order, encodes every element
(the neutral one included) uniquely, rejects elements outside the prime-order
subgroup, hashes to elements of unknown discrete log and samples scalars
uniformly up to negligible bias.

A backend subclasses `Group` from [`vsslib/backend`](./src/backend/abstract.ts)
and replaces `initBackend(...)`; it reports invalid encodings with
`BadPointError` or `BadScalarError`. An alternative implementation of a
built-in system, e.g. a native or WASM one, interoperates with it given the
same group parameters, point encoding and hash to the group.

## Installation

```
npm install vsslib
```

Requires Node.js 20.19 or later, or a bundler for browsers: the package is
CommonJS but uses no Node APIs at runtime. See
[Browser security](./SECURITY.md#browser-security).

## Development

### Tests

```
$ ./test.sh --help
```

Tests run on `node:test`, with tsx compiling the sources, one process per spec
file. Outside watch mode, a run in which no test ran fails.

`./test.sh --browsers` runs the flows in Chromium, Firefox and WebKit through
`playwright-core`, which downloads no browsers itself; CI runs it on schedule
and on demand. Install the browsers once, as your user:

```
$ npx --no-install playwright-core install
```

`--no-install` keeps npx from fetching and executing a misspelled package. If a
browser lacks system libraries, run
`sudo ./node_modules/.bin/playwright-core install-deps`.

### Examples

```
$ npx tsx examples/dkg.ts --help    # also sss.ts, vss.ts and tss.ts
```

[`examples`](./examples/dkg.ts) holds complete flows (SSS, VSS with verifiable
public key recovery, DKG on top of the latter, and
[threshold Schnorr signatures](./examples/tss.ts) after Stinson and Strobl,
with key and combined commitment computed by DKG), with the parties of every
step marked; the tests run them.

### Benchmarks

```
$ ./bench.sh --help
```

See [Measurement setup](./PERFORMANCE.md#measurement-setup).

### Documentation

```
$ npm run docs
```

### Dependencies

`@noble/curves` and `@noble/hashes` are pinned exactly, esbuild within tsx's
range, and the CI Node.js image by digest; nothing updates them automatically.
To bump them:

1. Take only versions at least 7 days old (`npm view <package> time`).
2. Bump `@noble/curves` with `@noble/hashes` (curves pins hashes exactly),
   esbuild with tsx, and `playwright-core` with the Playwright image of the
   `browsers` job.
3. For the CI image, take the newest `22.x` tag and its index digest (see
   `.gitlab-ci.yml`).
4. After `npm install`, check that `npm ls @noble/hashes esbuild` lists one
   version of each, and run `npm audit signatures` and the tests.
