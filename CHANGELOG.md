# CHANGELOG

All notable changes to this project will be documented in this file.


## Unreleased

### Breaking changes

- Node.js 20.19 or later is required.
- The package is published with an `exports` map; import from `vsslib`, `vsslib/backend` and `vsslib/nizk`.
- `unpackScalar` and `unpackPoint` are renamed to `parseScalar` and `parsePoint`, and `combinePublics` to `addPublics`.
- `addSecrets` is async.
- `verifyFeldmanCommitments` and `verifyPedersenCommitments` take `(ctx, commitments, [pedersenBase,] share, [binding], threshold)`.
- `verifyFeldmanCommitments`, `verifyPedersenCommitments`, `parseFeldmanPacket` and `parsePedersenPacket` take a required `threshold` and reject any other number of commitments.
- `combineSecretShares` and `combinePublicShares` take a required `threshold`, and `recoverPublic` takes `(ctx, packets, threshold, options)`. All three throw `InvalidInput` on fewer than `threshold` shares; `recoverPublic` throws `InvalidPublicShare` if fewer than `threshold` packets are valid.
- `ShamirSharing.createFeldmanPackets()` and `ShamirSharing.createPedersenPackets(pedersenBase)` are replaced by the functions `createFeldmanPackets(sharing)` and `createPedersenPackets(sharing, pedersenBase)`, which use the group of the sharing.
- `createPedersenPackets` no longer returns `bindings`; read `packet.binding` instead.
- `InvalidSecret` is removed.
- `extractPublicShare` is removed; use `extractPublic(ctx, share.value)` with the index of the share.
- Scalars are encoded little-endian with fixed width, `Group.scalarBytes` bytes. `parseScalar` and every function taking a secret, `extractPublic`, `isKeypair`, `isEqualSecret` and `addSecrets` included, reject any other length, zero and values not below the group order.
- NIZK challenges are computed over a length-prefixed, labelled encoding of their input, and Schnorr packet proofs cover the share index. Proofs and packets produced by 1.0.0 do not verify.
- Share indexes must be distinct positive safe integers; violations throw `InvalidInput`, also from `recoverPublic` regardless of `errorOnInvalid`.
- Hash algorithms outside `Algorithms` throw `InvalidInput`.
- `randomNonce(nrBytes)` throws `InvalidInput` unless `nrBytes` is an integer from 1 to 65536; a size of 0 or `null` no longer falls back to 16 bytes.
- Custom backends: `Group.buff2Point` is renamed to `bytesToPoint`, `Group.bytesToScalar` is removed, and `Group` declares the abstract `hashToPoint(msg, dst)`. In the elliptic backend, `EcGroup.curve` is removed; the wrapped curve is internal.

### Added

- Browser support through bundlers. Hashing uses `@noble/hashes`, now a direct dependency, and randomness comes from `crypto.getRandomValues`, so that no Node APIs are needed at runtime.
- Backends `ristretto255`, `decaf448`, `secp256k1`, `p256`, `p384` and `p521`. SEC1 points are encoded compressed, with `0x00` for the point at infinity.
- `derivePedersenBase(ctx, seed)`, which hashes a public seed to a group element of unknown discrete log.
- `Group.expSecret(point, scalar)`, exponentiation by a secret scalar, and `Group.blindsNatively(point)`, which tells whether `exp` blinds secret scalars for `point`. Custom backends inherit a default that always splits the scalar; override `blindsNatively` only for points the backend blinds, and as a property like the other `Group` members, since a method would be shadowed by the default.
- `Group.expPublic(point, scalar)`, exponentiation by a public scalar that may run in variable time. It defaults to `exp`; the elliptic backends use noble's `multiplyUnsafe`. Custom backends may override it, as a property, with a faster variable-time multiplication.
- `computeLambdas(ctx, indexes)`, the Lagrange coefficients at zero of all given indexes, computed with a single modular inversion.
- Root exports of `verifyFeldmanCommitments`, `verifyPedersenCommitments`, the public types and the errors `VssError`, `BadGroupError` and `ShamirError`. Every error derives from `VssError`.
- Type exports of `Elliptic`, the type of `System`, and of `EcGroup` and `EcPoint` from `vsslib/backend`, the types of the elliptic backends.

### Security

- Points outside the prime-order subgroup are rejected, and so are the neutral element and the generator as Pedersen base.
- Non-canonical point and scalar encodings are rejected, secrets included.
- Scalars are sampled without bias; the bias was about 1.3% on `jubjub`.
- A dealer can no longer share with a degree other than the announced threshold.
- Fewer than threshold shares can no longer be combined, also when `recoverPublic` drops invalid packets.
- Share indexes are validated and bound to Schnorr packet proofs.
- Predefined share indexes must be distinct positive integers.
- `isEqualSecret`, `isEqualPublic` and `isKeypair` compare canonical encodings in constant time.
- Scalars are encoded without conversion to strings, which ran in variable time and copied secrets to the heap.
- The random bytes from which scalars are sampled are wiped after use.
- Exponentiations by secret scalars that noble does not blind, i.e., of non-generator points on `ed25519`, `ed448`, `jubjub` and `ristretto255` and of every point on `decaf448`, split the scalar with a fresh random factor. Pedersen dealing is up to about twice as slow on these curves, and every secret operation about twice as slow on `decaf448`.
- `@noble/curves` and `@noble/hashes` are pinned to exact versions, so that installing vsslib never resolves an untested noble release. Applications that depend on another noble version get a second copy.

### Performance

- Verification of Feldman and Pedersen commitments raises the commitments to powers of the share index through `expPublic`. Verifying and parsing Feldman packets takes 31-61% less time on `ed25519` and `decaf448` and 89-95% less on `secp256k1` and `p521`, Pedersen packets 22-54% and 73-91% less; a DKG with 10 parties takes 12-14% and 45-46% less time, respectively.
- `shareSecret` without predefined shares samples the coefficients of the sharing polynomial directly instead of interpolating, and interpolation builds the Lagrange basis in quadratic instead of cubic time; `shareSecret` takes 45% less time at threshold 5 and about 90% less at threshold 25.
- The sharing polynomial is evaluated by Horner's rule over its coefficients instead of the barycentric formula, which inverted once per point and call; `getSecretShares` takes 78-93% less time.
- Lagrange coefficients are computed over a common denominator, whose inversions for all shares are batched into one; before, every difference of indexes was inverted. `combineSecretShares` takes 12-22% less time at threshold 5, 80-84% less at threshold 25 and 93-94% less at threshold 100, and `computeLambda` inverts once instead of once per other index. `shareSecret` with predefined shares inverts the denominators of the Lagrange basis in a batch, and takes 43-55% less time at thresholds 50 and 100.

### Fixed

- `recoverPublic` with `errorOnInvalid: false` interpolates over the valid shares only.
- VSS verification no longer rejects valid shares once `index ** j` exceeds 2^53.
- `generateSecret` returns an encoded scalar consistent with the recombined secret.


## 1.0.0 2024-10-15

This is the first documented release version.
