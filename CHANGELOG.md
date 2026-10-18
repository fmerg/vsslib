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
- `createPedersenPackets` no longer returns `bindings`; read `packet.binding` instead.
- `InvalidSecret` is removed.
- Scalars are encoded little-endian with fixed width, `Group.scalarBytes` bytes. `parseScalar` and every function taking a secret, `extractPublic`, `isKeypair`, `isEqualSecret` and `addSecrets` included, reject any other length, zero and values not below the group order.
- NIZK challenges are computed over a length-prefixed, labelled encoding of their input, and Schnorr packet proofs cover the share index. Proofs and packets produced by 1.0.0 do not verify.
- Share indexes must be distinct positive safe integers; violations throw `InvalidInput`, also from `recoverPublic` regardless of `errorOnInvalid`.
- Hash algorithms outside `Algorithms` throw `InvalidInput`.
- Custom backends: `Group.buff2Point` is renamed to `bytesToPoint`, `Group.bytesToScalar` is removed, and `Group` declares the abstract `hashToPoint(msg, dst)`. In the elliptic backend, `EcGroup.curve` is replaced by `EcGroup.Point`.

### Added

- Backends `ristretto255`, `decaf448`, `secp256k1`, `p256`, `p384` and `p521`. SEC1 points are encoded compressed, with `0x00` for the point at infinity.
- `derivePedersenBase(ctx, seed)`, which hashes a public seed to a group element of unknown discrete log.
- Root exports of `verifyFeldmanCommitments`, `verifyPedersenCommitments`, the public types and the errors `VssError`, `BadGroupError` and `ShamirError`. Every error derives from `VssError`.

### Security

- Points outside the prime-order subgroup are rejected, and so are the neutral element and the generator as Pedersen base.
- Non-canonical point and scalar encodings are rejected, secrets included.
- Scalars are sampled without bias; the bias was about 1.3% on `jubjub`.
- A dealer can no longer share with a degree other than the announced threshold.
- Fewer than threshold shares can no longer be combined, also when `recoverPublic` drops invalid packets.
- Share indexes are validated and bound to Schnorr packet proofs.
- Predefined share indexes must be distinct positive integers.

### Fixed

- `recoverPublic` with `errorOnInvalid: false` interpolates over the valid shares only.
- VSS verification no longer rejects valid shares once `index ** j` exceeds 2^53.
- `generateSecret` returns an encoded scalar consistent with the recombined secret.


## 1.0.0 2024-10-15

This is the first documented release version.
