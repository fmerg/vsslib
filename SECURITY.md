# Security

:warning: **This library requires a security audit. Use it at your own risk for
the moment.**

This document describes what vsslib does against side channels, what it leaves
to the caller, and how it validates input. Usage is described in
[USAGE.md](./USAGE.md), and the cost of the measures below in
[PERFORMANCE.md](./PERFORMANCE.md).

## Side-channel attacks

Strict resistance against side channels cannot be attained in JavaScript. The
language is garbage-collected and just-in-time compiled, its `BigInt`
arithmetic, which vsslib and its backends use for scalars, makes no promise of
running in time independent of the operands, and secret values may be copied
around the heap beyond the control of any library. Vsslib therefore removes the
known leaks of its own code by algorithmic means and keeps the remaining
exposure low. This reduces, but does not eliminate, what a timing or memory
observer can learn; applications guarding high-value, long-lived keys against
co-located attackers should consider a native implementation.

### Comparisons and encodings

Comparisons involving secrets run in constant time. A comparison that returns
at the first difference reveals by its running time where two values differ,
and over repeated attempts the values themselves. Since vsslib admits only
canonical encodings, two values are equal exactly when their encodings are, so
`isEqualSecret`, `isEqualPublic` and `isKeypair` compare encodings byte by byte
without early exit, after parsing them, so that invalid encodings are still
rejected. For the same reason, scalars are encoded to bytes by checking them
against the fixed scalar length, rather than measuring them by conversion to a
string, which would run in variable time and leave a copy of the secret on the
heap.

### Exponentiation by secret scalars

Exponentiation by secret scalars, such as shares, coefficients of the sharing
polynomial, Pedersen bindings, secret keys and NIZK nonces, is the most exposed
operation, since it is long and its timing depends on the scalar. The elliptic
backends rely on [`noble-curves`](https://github.com/paulmillr/noble-curves),
which multiplies with a fixed sequence of operations and blinds the scalar with
a random multiple of the group order. It blinds every point on the curves of
cofactor one (`secp256k1`, `p256`, `p384`, `p521`), but on the cofactored
curves only its own base point, i.e. the generator of `ed25519`, `ed448`,
`jubjub` and `ristretto255`. On `decaf448` it blinds no point, so vsslib
multiplies the generator through the base point of `ed448` instead (see
[Generator of decaf448](./PERFORMANCE.md#generator-of-decaf448)).

A leak in an unblinded multiplication accumulates over repeated calls with the
same scalar, e.g. when a shareholder verifies its long-lived Pedersen binding,
and partial leakage of NIZK nonces over many proofs is known to suffice for
lattice-based key recovery. Vsslib therefore performs every exponentiation by a
secret scalar through `Group.expSecret`, which uses the backend's exponentiation
directly only where it blinds natively, as reported by `Group.blindsNatively`.
Otherwise it splits the scalar as `P^s = (P^r)^(s/r)` for a fresh random `r`, so
that each of the two multiplications sees a uniform scalar independent of `s`
and leakage does not accumulate across calls.

- The split is multiplicative because the additive `P^r * P^(s - r)` would
  reduce `s - r`, which branches on whether `s < r` and would leak an estimate
  of `s` over many calls; partial leaks of both halves would moreover combine
  linearly.
- Modular inversion runs in variable time as well, so `r` is inverted as
  `u / (r * u)` for a second random `u`, which shows the inversion only a value
  independent of `r`.
- The split costs a second multiplication and an inversion: Pedersen dealing is
  up to about twice as slow on the Edwards curves, which the
  [Pedersen base table](./PERFORMANCE.md#pedersen-base-table) partly recovers;
  the curves of cofactor one are unaffected.

### Public scalars

Vsslib never calls `Group.exp` directly: secret scalars go through
`Group.expSecret`, and public ones through `Group.expPublic` and
`Group.multiExpPublic`, which may run in variable time. The elliptic backends
implement them by noble's variable-time multiplication and multi-scalar
multiplication. They raise the VSS commitments to the share index (see
[Horner's method](./PERFORMANCE.md#horners-method)), combine public shares with
their Lagrange coefficients (see
[Multi-exponentiation](./PERFORMANCE.md#multi-exponentiation)), and verify NIZK
proofs (see [NIZK verification](./PERFORMANCE.md#nizk-verification)). Custom
backends inherit the split and should override `blindsNatively` only for points
their exponentiation blinds. `expPublic` defaults to `exp` and `multiExpPublic`
to one `expPublic` per point; overrides of either may run in variable time,
since they never receive secrets.

### Memory

`BigInt` values are immutable and cannot be overwritten, so the scalars vsslib
computes with stay in memory until garbage collection, where heap snapshots,
core dumps or swap may expose them. Vsslib wipes the byte buffers it controls,
namely the random bytes from which secret scalars are sampled. The byte arrays
it returns, such as secrets, secret shares and bindings, belong to the caller,
who should overwrite them, e.g. with `fill(0)`, once they are no longer needed,
and drop references to objects holding secrets, such as a `ShamirSharing`, as
soon as possible.

The remaining arithmetic on secrets, i.e. evaluation of the sharing polynomial,
interpolation over predefined shares, combination of shares and computation of
NIZK responses, runs on `BigInt` and is not constant-time in principle. Since it
involves uniformly random full-width values, whose length changes only with
negligible probability, the information its timing exposes is expected to be
small. A fixed-width scalar representation would not remove it, since every
scalar becomes a `BigInt` again inside noble.

## Browsers

In a browser, vsslib shares the JavaScript engine with whatever else the page
loads, so the precautions above meet a stronger adversary. Scripts of the same
origin, including third-party dependencies and analytics, can read any value
reachable from the page, secrets and shares included, and so can browser
extensions with access to the page. Cross-origin code can still measure timing,
e.g. through shared caches and high-resolution timers, which site isolation and
cross-origin isolation mitigate but do not remove. Applications handling
secrets in the browser should keep them in a dedicated context, e.g. a Web
Worker or a separate origin with a strict Content Security Policy, load vsslib
from a pinned and integrity-checked bundle, and wipe the returned byte arrays
as described above.

Randomness comes from `crypto.getRandomValues`, which browsers and Node.js back
by the operating system's generator. It limits a single call to 65536 bytes, so
`randomNonce` accepts sizes from 1 to 65536 bytes.

## Input validation

The API exchanges scalars and group elements as bytes and parses every input
before use, throwing `InvalidInput` on anything that is not a canonical
encoding.

- Scalars are little-endian, of the fixed length of the backend, nonzero and
  below the group order.
- Group elements must lie in the prime-order subgroup, so that points with a
  small-order component, which could vanish from verification equations, are
  rejected.
- The commitments of NIZK proofs are the exception: verification only compares
  them with products of subgroup elements, which a point with a small-order
  component never equals, so they are only checked to be canonical points of
  the curve, through `Group.parseCurvePoint`. This spares a full multiplication
  per proof on `ed25519`, `ed448` and `jubjub`; custom backends keep the full
  check unless they override `Group.validateCurvePoint`.
- Share indexes must be distinct positive safe integers.
- The Pedersen base may be neither the neutral element nor the generator, whose
  discrete logs are known.

## Replay attacks

A NIZK proof verifies wherever its statement does, so a proof captured in one
session can be replayed in another. NIZK proofs, and the Schnorr packets of
[verifiable public recovery](./USAGE.md#verifiable-public-recovery), therefore
accept a nonce, which enters the challenge, so that a proof verifies only under
the same nonce. A nonce can be any bytestring, e.g. random bytes from
`randomNonce`, a session identifier, a synchronized counter or a combination
thereof; designing it securely for the application is the caller's
responsibility. Schnorr packets also bind the share index, so that a proof
cannot be presented for another index.
