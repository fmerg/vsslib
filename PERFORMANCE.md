# Performance

## Overview

Gains are changes of median running time, on `ed25519` and `decaf448` for the
Edwards curves and `secp256k1` and `p521` for the Weierstrass curves. They fall
into three groups: cheaper [scalar arithmetic](#scalar-arithmetic), a lower
cost of protecting [secret exponentiation](#secret-exponentiation), and
variable-time [public exponentiation](#public-exponentiation), where scalars are
public and timing reveals nothing
(see [SECURITY.md](./SECURITY.md#public-scalars)).

### Measurement setup

The [benchmarks](./README.md#benchmarks) (`./bench.sh`) measure the high-level
operations, each as the local computation of one party: dealer, shareholder or
combiner. Protocol runs such as VSS or DKG are not benchmarked: the parties run
in parallel, and the rounds between them depend on the network and the
application.

Each run is a fresh `node` process loading an esbuild bundle of the benchmarks
and the library sources, with noble loaded natively, as by users of `dist`
(under tsx, its hashes run up to 35 times slower). Cases run round-robin on
seeded inputs and report medians over runs; `range` shows how quiet the machine
was. Runs record the machine conditions, and comparisons warn when they differ.
The governor, turbo boost, throttling and background load are not controlled,
so take both sides of a comparison back to back.

The figures come from the benchmarks on an Intel Core
i5-12450H pinned to its performance cores under the `powersave` governor, with
Ubuntu 24.04.5 (Linux 6.8), Node.js 22.22.1 and `@noble/curves` 2.4.0. Absolute
times depend on the machine; compare the relative changes instead, including
operations a change should not affect as a control:

```
$ git switch --detach <before>
$ ./bench.sh -m shamir,feldman,pedersen,recovery -s ed25519,decaf448,secp256k1,p521 \
    -n 5,50 -t 3,25 --cpus 0-7 -r 5 --save before
$ git switch -
$ ./bench.sh -m shamir,feldman,pedersen,recovery -s ed25519,decaf448,secp256k1,p521 \
    -n 5,50 -t 3,25 --cpus 0-7 -r 5 --compare before
```

`--cpus 0-7` pins the runs to the performance cores. `-r 5` measures each case
in 5 fresh processes per side; a case counts as changed only if the runs of
both sides do not overlap, which unchanged code does by chance less than 1% of
the time. To focus on a few operations over a wider range, select them by name
or glob:

```
$ ./bench.sh -o "combine*,recoverPublic" -s ed25519,decaf448,secp256k1,p521 \
    -n 100 -t 5,25,50,100 --cpus 0-7 -r 5 --compare <baseline>
```

## Scalar arithmetic

Arithmetic modulo the group order is cheap next to group operations, so these
gains show mostly where an operation does little else: sampling the sharing
polynomial, computing the shares and combining them.

### Polynomial sampling

Without predefined shares, `shareSecret` samples the coefficients of the
sharing polynomial directly, with the secret as constant term, instead of
interpolating the secret at `0` and random values at `1, ..., t - 1`. The
distribution is the same, and `shareSecret`, a microsecond-range operation, is
about 45% faster at threshold 5 and 90% at threshold 25. With predefined shares
it still interpolates, in quadratic instead of cubic time.

### Horner's method

Computing the shares evaluates the sharing polynomial at each index by Horner's
rule over its coefficients, instead of the barycentric form of the
interpolating polynomial, which takes one modular inversion per interpolation
point at every call. Horner's rule needs no inversion and reduces modulo the
order only at the end, or whenever the intermediate value outgrows the order by
256 bits. This makes `getSecretShares` about 80-95% faster on every curve
(92 µs instead of 1.21 ms for 50 shares at threshold 25 on `ed25519`);
elsewhere it shows only in `createFeldmanPackets`, by up to a fifth with 50
shares. Horner's rule also evaluates commitments in the exponent (see
[Commitment verification](#commitment-verification)).

### Common denominator

Combining shares weights each by its Lagrange coefficient at zero, the product
of `x_j / (x_j - x_i)` over the other indexes; computed one by one, the
coefficients of `k` shares take `k(k - 1)` modular inversions, each a run of
the extended Euclidean algorithm on big integers. Vsslib writes them over a
common denominator, as `N / (x_i D_i)` with `N` the product of the indexes and
`D_i` that of the differences, and inverts all denominators at once by
Montgomery's trick, with one inversion and three multiplications per
coefficient. The products of the small indexes are reduced modulo the order
only once they outgrow it by 256 bits.

This makes `combineSecretShares`, which consists mostly of these coefficients,
80-95% faster from threshold 25 on (0.66 instead of 10.4 ms for 100 shares on
`ed25519`) and 10-20% at threshold 5, alike on every curve. Interpolation over
predefined shares in `shareSecret` inverts in a batch too and is 10-25% faster
at threshold 25, about twice as fast from 50 on. Combining public shares barely
gains, since raising the shares to the coefficients dominates it (see
[Multi-exponentiation](#multi-exponentiation)).

## Secret exponentiation

Exponentiation by secret scalars, such as shares, polynomial coefficients and
bindings, must not leak them through timing (see
[SECURITY.md](./SECURITY.md#exponentiation-by-secret-scalars)). This protection
costs extra work, which the optimizations below lower without weakening it.

### Split of secret exponentiations

noble blinds the scalar for every point on the Weierstrass curves, but on the
cofactored curves only for its own base point, the generator. Every other
exponentiation by a secret, e.g. of the Pedersen base, vsslib splits: for a
fresh random `r`, it computes `Q = P^r` and then `Q^(s/r)`, which equals `P^s`,
so that neither multiplication sees `s`. It inverts `r` as `u / (r * u)` for a
second random `u`, so that the variable-time inversion never sees `r` either.

The split costs an inversion and a second multiplication, on the fresh point
`Q`, which has no precomputed table: on the Edwards curves, it makes Pedersen
dealing 65-85% and Pedersen verification 15-40% slower, and every secret
operation on `decaf448` about twice as slow; the Weierstrass curves are
unaffected. The two optimizations below recover much of this.

### Generator of decaf448

noble recognizes its base point by object identity. The generator of
`decaf448` is represented by twice the base point of `ed448`, but as another
object, so noble blinds none of its multiplications, and even exponentiations
of the generator would take the split. Vsslib instead computes `g^s` on
`decaf448` as twice `B^s`, with `B` the base point of `ed448`, which noble
blinds and multiplies through a precomputed table. Both groups have the same
prime order, and doubling the result avoids any arithmetic on `s`. Public
exponentiations of the generator take the same route, unblinded.

This makes the operations raising the generator of `decaf448` to secrets, i.e.
key and public share extraction, Feldman dealing and Schnorr proofs, 80-86%
faster, i.e. 5 to 7 times (0.60 instead of 4.23 ms per public key, against
0.44 ms on `ed448`). Verification, which raises the generator too, is about
70% faster for Feldman packets, 40% for Pedersen packets, a third for Schnorr
packets and a quarter in `recoverPublic`. Pedersen dealing gains 44%, since its
exponentiations of the Pedersen base still split.

### Pedersen base table

Pedersen dealing raises the base `h` to the secret binding coefficients, and
verification to the share's binding. Instead of parsing `h` anew and
multiplying it without precomputation in every operation, vsslib keeps up to 8
validated bases per backend class, evicting the least recently used, and on
the second use of a base attaches a precomputed table of its multiples, of
window 4, through the backend hook `Group.precomputeBase`. On the Weierstrass
curves, the whole exponentiation of `h` uses the table and is 4 to 4.5 times
faster; on the cofactored curves, only the first multiplication of the
[split](#split-of-secret-exponentiations) does, and it is 30-37% faster.

With a reused base, Pedersen dealing is 60-65% faster on the Weierstrass curves
(9.5 instead of 27.5 ms on `p521` at threshold 3) and 30-40% on the Edwards
curves. Verification is 55-60% and 25-30% faster at threshold 3, and 40-50%
and 10-20% at threshold 10, since evaluating the commitments grows with the
threshold and does not involve `h`. The table pays off from the third use of a
base: the first only parses and keeps it, the second builds the table at the
cost of a few untabled multiplications (about 6 ms on `ed25519`, 21 ms on
`p521`). The first tables built in a process also run unoptimized code, a
one-off of up to about 12 ms. A table takes 107 KB on `secp256k1` to 315 KB on
`p521`.

## Public exponentiation

Where every scalar is public, as in verification and in the combination of
public shares, timing reveals nothing. Exponentiation can then skip the
protections of secret exponentiation and run in variable time, whose cost grows
with the length of the scalar.

### Commitment verification

Verifying a VSS share with index `i` evaluates the sharing polynomial in the
exponent, `C_0 * C_1^i * ... * C_(t-1)^(i^(t-1))` over the commitments, by
Horner's rule as `C_0 * (C_1 * (C_2 * ...)^i)^i`. Each step raises to `i` by
variable-time exponentiation, which costs a few doublings and additions for a
small index, where constant-time exponentiation costs a full multiplication
whatever the scalar. Horner's rule keeps every scalar as short as `i`, whereas
the powers `i^j` would grow to the length of the order. This makes Feldman
verification 30-60% faster on the Edwards curves and 90-95% on the Weierstrass
curves (3.3 instead of 47 ms on `secp256k1` for 50 shares at threshold 25), and
Pedersen verification 20-55% and 75-90% respectively. The Edwards curves gain
less, since the subgroup check of every parsed commitment, a full
multiplication, remains.

### Multi-exponentiation

Combining public shares `y_1, ..., y_k` computes the product of the
`y_i^(lambda_i)` over their Lagrange coefficients. Instead of one constant-time
exponentiation per share, vsslib computes it as one multi-exponentiation by
Pippenger's bucket method, which shares a single chain of doublings among all
shares; below 4 shares, or 16 on `secp256k1`, whose single multiplications an
endomorphism already accelerates, it multiplies each share in variable time.
Moreover, `recoverPublic` parses every public share once, not separately to
verify and to combine it.

From threshold 25 on, this makes `combinePublicShares` 65-80% faster on the
Weierstrass curves (14 instead of 47 ms for 25 shares on `secp256k1`), 50-60% on
`decaf448` and about a third on `ed25519`, where the subgroup check of every
parsed share costs about as much as its exponentiation and remains. At
threshold 5, the gain is 35-60% on the Weierstrass curves and about 15% on the
Edwards curves. `recoverPublic` is 20-40% faster; most of its time goes to the
NIZK proof of each packet (see [NIZK verification](#nizk-verification)).

### NIZK verification

Verifying a NIZK proof checks, for each row of the relation, that the proof's
commitment equals the product of the row's points raised to the responses and
of the statement raised to the negated challenge, all of them public. Vsslib
computes each row as one variable-time multi-exponentiation instead of
constant-time exponentiations. Moreover, it checks the commitments of the
proofs only to be canonical curve points, skipping the subgroup check, a full
multiplication on `ed25519`, `ed448` and `jubjub`: verification compares them
with subgroup elements, which a point outside the subgroup never equals (see
[Input validation](./SECURITY.md#input-validation)).

This makes `parseSchnorrPacket` about 50% faster on `secp256k1` and 25% on
`p521`, mostly through variable-time multiplication, and 25-30% on `ed25519`
and `ed448`, mostly through the skipped subgroup check. `decaf448`, whose
subgroup check is cheap, does not gain and is up to 6% slower. `recoverPublic`,
which verifies one proof per packet, changes by about the same (134 instead of
261 ms for 100 packets on `secp256k1`).
