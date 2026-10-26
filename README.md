# vsslib

Interfaces for Verifiable Secret Sharing (VSS) in TS/JS

:warning: **This library requires security audit. Use at your own risk for
the moment.**

Vsslib provides modular building blocks for implementing threshold-cryptographic protocols
based on Verifiable Secret Sharing (VSS), e.g., Distributed Key Generation (DKG) schemes.

## Quick example

**Local setup**

Involved parties agree on a common cryptosystem.

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

Broadcast the commitments and send the packets to the respective shareholders
in private.

**Shareholders' side**

```js
import { parseFeldmanPacket, InvalidSecretShare } from "vsslib";

// Extract and verify secret share from received packet
try {
  const { share } = await parseFeldmanPacket(ctx, commitments, packet, t);
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

See [`examples`](./examples/dkg.ts) for complete flows of SSS, VSS and DKG.

## Overview

Vsslib provides modular building blocks for implementing threshold-cryptographic protocols
based on Shamir's Secret Sharing (SSS). It focuses on primitives that make the
sharing process verifiable on behalf of the involved parties
([Feldman](./USAGE.md#feldman-scheme) and [Pedersen](./USAGE.md#pedersen-scheme) VSS schemes)
and as such applicable in contexts with zero or low trust assumptions.

### Backend

Vsslib is designed to be agnostic with respect to the underlying cryptosystem
and to admit pluggable backends.
It abstracts away algebraic details by internally interacting with a generic cryptosystem interface,
which backend implementations are expected to conform with.

Vsslib comes with several backends based on
[`noble-curves`](https://github.com/paulmillr/noble-curves),
but any implementation wrapped with the prescribed interface
should do the job, provided that it
- operates over a group of prime order,
- gives every element, including the neutral one, a unique encoding,
- rejects elements outside the prime-order subgroup,
- hashes to group elements of unknown discrete log, and
- samples scalars uniformly up to negligible bias.

A backend is a subclass of `Group` from `vsslib/backend`, whose instance is
passed to the API in place of `initBackend(...)`; its members may be written as
methods or as properties. Invalid encodings are reported by throwing
`BadPointError` or `BadScalarError`, which parsing turns into `InvalidInput`.
An alternative implementation of a built-in system, e.g. a native or WASM one,
interoperates with it if it has the same group parameters, point encoding and
hash to the group, which enter NIZK challenges and Pedersen bases.

Refer to [`vsslib/backend`](./src/backend/abstract.ts) for details.

## Documentation

[USAGE.md](./USAGE.md) walks through the operations with examples,
[SECURITY.md](./SECURITY.md) describes the precautions against side channels,
what is left to the caller and how input is validated, and
[PERFORMANCE.md](./PERFORMANCE.md) explains and measures the optimizations.
[CHANGELOG.md](./CHANGELOG.md) lists the changes per release. `npm run docs`
builds the API reference in `docs/`, together with these documents.

## Installation

```
npm install vsslib
```

Requires Node.js 20.19 or later, or a browser through a bundler such as esbuild,
Vite or webpack. The library uses no Node APIs at runtime: it hashes with
[`noble-hashes`](https://github.com/paulmillr/noble-hashes) and samples
randomness with `crypto.getRandomValues`, which every modern browser and
Node.js provide. The package is built as CommonJS, so loading it in a browser
without a bundler, e.g. from a CDN as an ES module, is not supported yet. See
[Browsers](./SECURITY.md#browsers) for the security implications.

## Development

```
$ ./test.sh --help                  # tests, over all systems unless -s <SYSTEM>
$ ./bench.sh --help                 # benchmarks of the high-level operations
$ npx tsx examples/dkg.ts --help    # also sss.ts and vss.ts
$ npm run lint
$ npm run typecheck                 # library, tests, benchmarks and examples
$ npm run build
$ npm run docs                      # API reference and guides in docs/
```

### Tests

Tests run on Node's built-in test runner (`node:test`), with tsx compiling the
sources, one process per spec file. For CI, `./test.sh` also writes a JUnit
report to `coverage/junit.xml` (`coverage/browsers.xml` with `--browsers`),
except with a `--test-reporter` of your own, which replaces the default
reporters. Except in watch mode, it fails a run in which no test ran, e.g. for
a name pattern that matches nothing, counted by
[`tests/count-reporter.mjs`](./tests/count-reporter.mjs).

### Layout

[`src/operations`](./src/operations/index.ts) holds the library operations,
one module per scheme (`shamir`, `feldman`, `pedersen`, `recovery`, plus
`secrets`), each with both directions of the scheme, e.g., packet creation and
parsing. They build on the core modules of `src` (backends, NIZK proofs,
interpolation), which never import from them. Tests in `tests/operations`
mirror these modules.

### Examples

[`examples`](./examples/dkg.ts) holds complete flows: SSS, VSS with verifiable public
recovery, and DKG built on top of the latter. They are reference
implementations, with the parties of every step marked, and are also run by
the tests.

### Browser check

[`tests/browser.spec.ts`](./tests/browser.spec.ts) bundles the entry points of
the library for the browser with esbuild and fails on any Node module, also one
required inside `try`, and on any reference to Node globals such as `Buffer` or
`process`. It then runs SSS, VSS with public recovery and NIZK proofs from the
bundle in a Node `vm` context that exposes only `crypto` and `TextEncoder`. It
thereby guards against Node APIs leaking into the library, but does not bundle
the compiled `dist`.

[`tests/browser/engines.ts`](./tests/browser/engines.ts) runs the same flows in
Chromium, Firefox and WebKit through `playwright-core`, which downloads no
browsers itself. CI runs it on schedules and on demand, in the Playwright image
that ships the browsers. To run it locally

```
$ npx --no-install playwright-core install      # once: browsers of the pinned release
$ npm run test:browsers                         # results also in coverage/browsers.xml
$ BROWSERS=webkit npm run test:browsers -- -s ed25519   # ./test.sh --help
```

`--no-install` makes npx run only the locked `playwright-core` and fail on a
misspelled name, which plain npx would fetch from the registry and execute.
Install the browsers as your user, not with sudo, which would put them in
root's cache. If a browser fails to launch for missing system libraries,
`sudo ./node_modules/.bin/playwright-core install-deps` installs them, or run
the tests in the CI image, which needs no installation:

```
$ docker run --rm -v "$PWD":/src:ro mcr.microsoft.com/playwright:<tag>@<digest> \
    bash -c 'cp -r /src /w && cd /w && rm -rf node_modules && npm ci && npm run test:browsers'
```

with the image of the `browsers` job in `.gitlab-ci.yml`. The container works
on a copy of the checkout, so the JUnit report stays inside it; the output
lists the failed checks.

### Benchmarks

Benchmarks cover the high-level operations of the library only (no backends
or internals), each as the local computation of one party: the dealer, a
shareholder or the combiner. Complete protocol runs such as VSS or DKG are not
benchmarked, since no party computes them as a whole: the parties run in
parallel, and the rounds between them depend on the network and on how the
application implements the protocol. See `--help` for modules, parameter
sweeps, output formats, columns and baselines.

#### Workers

Each run is a fresh `node` process that loads a bundle of the benchmarks and
the library sources, built by esbuild once per invocation with the target of
`dist` (`es2020`). Dependencies are left out of the bundle, so that node loads
the ESM-only `@noble/curves` and `@noble/hashes` natively, as it does for users
of `dist`. Running the sources through tsx instead would transform these
packages to CommonJS, which made their hashes up to 35 times slower. Baselines
record the runner, and comparisons warn against baselines taken through tsx.

#### Statistics

Each case runs in fresh processes, repeated round-robin over the cases on
seeded inputs, and is reported as medians over runs; `range` shows how quiet
the machine was. A case counts as changed only if its median moved beyond the
tolerance and the runs of both invocations do not overlap; unchanged code
passes this by chance 10% of the time with the default 3 runs per side, and
below 1% with 5.

#### CPUs

Runs record the machine conditions and comparisons warn when these differ.
Use the `performance` governor and, on CPUs with performance and efficiency
cores, pin the runs to one kind with `--cpus`; turbo boost, throttling and
background load are not controlled. Take the two sides of a comparison back to
back: under the `powersave` governor, the same code once measured twice as slow
an hour apart.

### Dependencies

`@noble/curves` and `@noble/hashes` are pinned exactly, so that installing
vsslib never resolves a noble release that was not tested with it; an
application that depends on another noble version gets a second copy. esbuild
is pinned within the `~0.28` range of tsx, so that both share one copy. CI runs
on a Node.js image pinned by digest (`.gitlab-ci.yml`). Nothing updates these
automatically; to bump them

1. `npm outdated` lists newer versions; `npm view <package> time` shows their
   release dates. Take a version only once it is at least 7 days old, which
   leaves time for a compromised release to be found and pulled.
2. Bump `@noble/curves` and `@noble/hashes` together: curves pins hashes exactly,
   so both must name the same version for npm to install one copy of hashes.
3. Bump esbuild together with tsx, within the range tsx accepts, and
   `playwright-core` together with the Playwright image of the `browsers` job,
   whose browsers must match it.
4. For the CI image, take the newest `22.x` tag and the digest of its index
   (see the comment in `.gitlab-ci.yml`).
5. Run `npm install`, check that `npm ls @noble/hashes esbuild` lists one
   version of each, and run `npm audit signatures`, lint, type check and tests.

### Publish

Update the CHANGELOG, then

```
$ npm version <patch|minor|major> -m "chore: release %s"
$ npm publish
$ git push --follow-tags
```

`npm publish` first runs lint, type check, tests and build (`prepublishOnly`),
and requires `npm login` or a token in `~/.npmrc`.
