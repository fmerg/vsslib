# Security

:warning: **This library requires a security audit. Use it at your own risk for
the moment.**

For usage, see [USAGE.md](./USAGE.md); for the cost of the measures below, see
[PERFORMANCE.md](./PERFORMANCE.md).

## Input validation

Inputs come from other parties, who may craft them. Vsslib parses every input
before use and throws `InvalidInput` on anything that is not a canonical
encoding of a valid value.

Scalars are encoded little-endian at the backend's fixed length and must be
nonzero and below the group order; group elements must be canonical encodings of
points in the prime-order subgroup. A scalar at or above the order would defeat
byte comparisons and make NIZK responses malleable; zero as a secret or key is
trivially known. On the cofactored curves, a point with a small-order component,
raised to a secret, reveals the secret modulo that order; in a verification
equation, the component vanishes for some scalars only (e.g. a forged commitment
verifies at some share indexes only).

## Browser security

In a browser, vsslib shares the JavaScript engine with everything the page
loads. Same-origin scripts (including third-party dependencies and analytics)
and browser extensions with access to the page can read any reachable value,
secrets and shares included. Cross-origin code can still measure timing (e.g.
through shared caches and high-resolution timers); site isolation and
cross-origin isolation mitigate this but do not remove it. Keep secrets in a
dedicated context (e.g. a Web Worker or a separate origin with a strict Content
Security Policy), load vsslib from a pinned and integrity-checked bundle, and
zeroize the returned byte arrays (see [Memory](#memory)).

Randomness comes from `crypto.getRandomValues`, backed by the operating system's
generator in browsers and Node.js. Since it caps a call at 65536 bytes,
`randomNonce` accepts 1 to 65536 bytes.

## Support for NIZK proofs

Threshold-cryptographic security against malicious shareholders is usually
attained through non-interactive zero-knowledge (NIZK) proofs for contextual
statements. Vsslib provides NIZK infrastructure (`vsslib/nizk`) for proving
knowledge of generic discrete-log-based linear relations over arbitrary groups
and hash functions.

### Replay attacks

In practice, plain usage of NIZK proofs is usually susceptible to replay
attacks. Vsslib allows inclusion of nonces when generating a NIZK proof, capable
of maintaining state between the verifier and the involved provers. A nonce can
be any bytestring, e.g., cryptographically secure random bytes, unique session
identifiers, synchronized counters, or combinations thereof. It is the user's
responsibility to ensure that its design is secure in the particular
application context.

### Challenge encoding

Vsslib hashes into the Fiat-Shamir challenge a label naming the proof type, the
group parameters (modulus, order, generator), the statement, the proof's
commitments, the `extras` and the nonce. It prefixes every field with its length
and every list with its count, so that distinct inputs never encode to the
same bytes. A proof thus verifies only for the same type, group, statement and
context.

## Side-channel attacks

Strict side-channel resistance is unattainable in JavaScript; the language is
garbage-collected and just-in-time compiled, its `BigInt` arithmetic (which
is used by vsslib and its backends) makes no constant-time promise, and
secrets may be copied around the heap beyond control. Vsslib tries to
remove the leaks of its own code algorithmically and to keep the remaining
exposure low. This reduces, but does not eliminate, what a timing or memory
observer learns; for high-value, long-lived keys against co-located attackers,
consider a native implementation (C/Rust) where constant-time techniques and
memory control are feasible.

### Comparisons and encodings

Vsslib compares secrets in constant time; it rejects invalid and non-canonical
encodings (so that equal values have equal bytes) and then accumulates the
differences without early returns. Only the lengths, which are fixed per group,
affect timing.

Encoding a scalar must not leak it through timing either. Measuring a `BigInt`
through its string conversion takes value-dependent time and leaves a copy on
the heap; vsslib encodes scalars at the fixed scalar length of the group and
only checks that the value fits.

### Exponentiation by secret scalars

Exponentiation by secret scalars (shares, sharing coefficients, Pedersen
bindings, secret keys, NIZK nonces) is the most exposed operation (long, with
scalar-dependent timing). The elliptic backends use
[`noble-curves`](https://github.com/paulmillr/noble-curves), which multiplies
with a fixed sequence of operations and blinds the scalar with a random multiple
of the group order. It blinds every point on the curves of cofactor one
(`secp256k1`, `p256`, `p384`, `p521`); on `ed25519`, `ed448`, `jubjub` and
`ristretto255` only the generator; on `decaf448` no point. It multiplies other
points unblinded, e.g. the Pedersen base or the points of a NIZK statement.

Whatever an unblinded multiplication leaks accumulates over repeated calls with
the same scalar (e.g. a shareholder verifying its long-lived Pedersen binding);
partial leaks of NIZK nonces over many proofs suffice for lattice-based key
recovery. Vsslib therefore exponentiates by secrets only through
`Group.expSecret`. Where the backend blinds the point (`Group.blindsNatively`),
it uses the backend's exponentiation; it raises the generator of `decaf448`
through the base point of `ed448`, which noble blinds (see
[Generator of decaf448](./PERFORMANCE.md#generator-of-decaf448)). Every other
exponentiation it splits: for a fresh random `r`, it computes `Q = P^r`, then
`Q^(s/r) = P^s`. Each multiplication sees a uniform scalar independent of `s`,
so that leakage does not accumulate.

- The split is multiplicative. An additive split `P^r * P^(s - r)` reduces
  `s - r` modulo the order, branching on whether `s < r`; over many calls with
  fresh `r`, the branch frequency estimates `s`. Partial leaks of both halves
  would also combine linearly into `s`.
- Modular inversion runs in variable time too, so vsslib inverts `r` as
  `u / (r * u)` for a second random `u`; the inversion sees only `r * u`, which
  is independent of `r`.
- The split costs an inversion and a second multiplication on the fresh point
  `Q`, which has no precomputed table. On the Edwards curves it makes Pedersen
  dealing 65-85% slower, partly recovered by the
  [Pedersen base table](./PERFORMANCE.md#pedersen-base-table); the curves of
  cofactor one are unaffected.

#### Public scalars

Exponentiation by public scalars (share indexes, Lagrange coefficients, NIZK
responses and challenges) needs no protection; vsslib runs it in variable time,
which is much faster. A secret passed to it would leak, so vsslib never calls
`Group.exp` directly: secret scalars go through `Group.expSecret`, public ones
through `Group.expPublic` and `Group.multiExpPublic` (on the elliptic backends,
noble's variable-time multiplication and multi-scalar multiplication).

Custom backends inherit the split and should override `blindsNatively` only for
points their exponentiation blinds. `expPublic` defaults to `exp` and
`multiExpPublic` to one `expPublic` per point; overrides of either may run in
variable time, since they never receive secrets.

### Memory

`BigInt` values are immutable and cannot be zeroized, so the scalars vsslib
computes with stay in memory until garbage collection, exposed to heap
snapshots, core dumps or swap. Vsslib zeroizes the buffers it controls: the
random bytes from which secret scalars are sampled. The byte arrays it returns
(secrets, secret shares, bindings) belong to the caller, who should zeroize them
once no longer needed (e.g. with `fill(0)`) and drop objects holding secrets
(e.g. a `ShamirSharing`) as soon as possible.

The remaining arithmetic on secrets (evaluating the sharing polynomial,
interpolating over predefined shares, combining shares, computing NIZK
responses) runs on `BigInt` and is not constant-time. Its operands are uniformly
random full-width values (their length varies only with negligible
probability), so its timing should expose little. A fixed-width scalar type
would not help, since noble converts every scalar back to `BigInt`.
