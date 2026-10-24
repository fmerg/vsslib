# Performance

Vsslib's operations were optimized step by step, each against the previous
implementation, and measured with the [benchmarks](./README.md#benchmarks)
under the [setup](#measurement-setup) below. Each section explains a change and
gives the measured changes of median running time; absolute times depend on the
machine. The security reasoning behind the variable-time steps is in
[SECURITY.md](./SECURITY.md#public-scalars).

## Horner's method

Horner's rule evaluates a polynomial of degree `t - 1` with `t - 1`
multiplications and additions, as `a_0 + x(a_1 + x(a_2 + ...))`, without
computing powers of `x`. Vsslib evaluates polynomials at the share indexes
`i = 1, ..., n` in two places: in the exponent, when verifying VSS commitments,
and over scalars, when computing the shares. Most of the gain does not come from
Horner's rule itself: verification already used it and became faster because
its steps became cheaper, whereas the sharing polynomial gains a lot in relative
terms on an operation that was cheap to begin with. Measured over `n = 10, 50`
shares and thresholds `t = 5, 25`:

| operation | `ed25519`, `decaf448` | `secp256k1`, `p521` | cause |
| --- | ---: | ---: | --- |
| verify/parse Feldman packets | -31% to -61% | -89% to -95% | [variable-time steps](#variable-time-steps-in-commitment-verification) |
| verify/parse Pedersen packets | -22% to -54% | -73% to -91% | [variable-time steps](#variable-time-steps-in-commitment-verification) |
| `getSecretShares` | -78% to -93% | -78% to -93% | [Horner's rule](#horners-rule-over-the-sharing-polynomial) |
| `createFeldmanPackets` (n = 50) | up to -23% | up to -22% | [Horner's rule](#horners-rule-over-the-sharing-polynomial) |
| `shareSecret` (t = 5 / t = 25) | -45% / -90% | -45% / -90% | [no interpolation](#sampling-instead-of-interpolation) |

Operations dominated by exponentiations by secret scalars or Lagrange
coefficients, such as `getPublicShares`, `createPedersenPackets` and the
combination of shares, are unchanged within noise.

### Variable-time steps in commitment verification

A share with index `i` is verified against the commitments `C_0, ..., C_(t-1)`
by computing `C_0 * C_1^i * C_2^(i^2) * ... * C_(t-1)^(i^(t-1))`, which vsslib
already did by Horner's rule as `C_0 * (C_1 * (C_2 * ...)^i)^i`. This had
however no effect on the cost, because the steps went through `Group.exp`,
which noble runs in constant time, with the same sequence of operations for
every scalar up to the group order. Raising to the small index `i` then costs as
much as raising to the large `i^j`, so that both forms cost about one full
multiplication per commitment. The steps now go through `Group.expPublic`,
which the elliptic backends implement by noble's variable-time multiplication,
whose cost grows with the length of the scalar, so that each step costs a few
doublings and additions. Measured on its own, this change accounts for nearly
all of the gains of verification in the table. Horner's rule makes it pay off in
full, since it keeps every scalar as short as `i`; with the powers `i^j`, the
scalars would grow by the length of `i` per term up to the full length of the
order. Variable time is safe here, since the index and the commitments are
public (see [Public scalars](./SECURITY.md#public-scalars)).

For example, parsing and verifying a Feldman packet with `n = 50, t = 25` takes
3.32 ms instead of 46.6 ms on `secp256k1`. The gain is smaller on the Edwards
curves (20.3 ms instead of 29.7 ms on `ed25519`), because each parsed commitment
is checked to lie in the prime-order subgroup, a full multiplication that
remains.

### Horner's rule over the sharing polynomial

The sharing polynomial used to be evaluated at each share index in the
barycentric form of the interpolating polynomial, with one modular inversion
per interpolation point at every call. It is now evaluated by Horner's rule
over its coefficients, with `t - 1` multiplications and a single reduction
modulo the order (also whenever the intermediate value outgrows the order by
256 bits, i.e. about every `256 / log2(i)` steps at share index `i`), which
cuts the time of `getSecretShares` by 78% to 93%. This is the gain of Horner's
rule proper, but on scalar arithmetic, which is cheap next to group operations: with `n = 50, t = 25` on `ed25519`,
`getSecretShares` takes 92 µs instead of 1.21 ms, whereas `getPublicShares`,
which raises the generator to each share, takes 11 ms. It is visible in
`createFeldmanPackets`, which evaluates the polynomial alongside cheaper group
operations.

### Sampling instead of interpolation

`shareSecret` used to construct the sharing polynomial by interpolating the
secret at `0` and random values at `1, ..., t - 1`. Without predefined shares,
it now samples the coefficients directly, with the secret as constant term,
which yields the same distribution without interpolation, so that
`shareSecret` takes 45% less time at `t = 5` and about 90% less at `t = 25`. This
is unrelated to Horner's rule, and again concerns scalar arithmetic in the
microsecond range.
With predefined shares, the polynomial is still interpolated, now building the
Lagrange basis in quadratic instead of cubic time; this case was not
benchmarked.

## Common denominator

The Lagrange coefficient of index `x_i` with respect to the indexes
`x_1, ..., x_k` of the combined shares is the product of `x_j / (x_j - x_i)`
over all `j` other than `i`. The combining operations used to compute each
coefficient separately and to invert every difference modulo the order, i.e.
`k(k - 1)` modular inversions for `k` shares, each a run of the extended
Euclidean algorithm on big integers. The coefficients are now written over a
common denominator, as `N / (x_i D_i)` with `N` the product of all indexes and
`D_i` the product of the differences, and the denominators of all coefficients
are inverted together by Montgomery's trick, with a single inversion and three
multiplications per coefficient, followed by one more to multiply by `N`.
Since indexes are small integers, these products are reduced modulo the order
only once they outgrow it by 256 bits: reducing at every step made them 2-3
times slower, and not reducing at all much slower for thousands of shares.
Measured on `combineSecretShares` with `n = 100` shares:

| threshold | `ed25519` | `decaf448` | `secp256k1` | `p521` |
| ---: | ---: | ---: | ---: | ---: |
| 5 | -15% | -17% | -12% | -22% |
| 25 | -84% | -80% | -84% | -80% |
| 50 | -91% | -91% | -91% | -90% |
| 100 | -94% | -94% | -93% | -94% |

For example, combining 100 secret shares on `ed25519` takes 662 µs instead of
10.4 ms. This concerns arithmetic on scalars only. `combinePublicShares` and
`recoverPublic` are unchanged within noise, since raising each share to its
coefficient costs far more than computing the coefficient: with `t = 25` on
`ed25519`, `combinePublicShares` takes 39 ms, of which the coefficients took
about 0.5 ms. The exponentiations were sped up afterwards (see
[Multi-exponentiation](#multi-exponentiation)).

`shareSecret` with predefined shares interpolates `t` points, which inverts the
`t` denominators of the Lagrange basis; these are now inverted in a batch too.
Measured with a separate script, since the benchmarks do not cover predefined
shares, it takes 10-25% less time at `t = 25` and 43-55% less at `t = 50, 100`.

## Multi-exponentiation

Combining public shares `y_1, ..., y_k` computes the product of `y_i^(lambda_i)`
over their Lagrange coefficients `lambda_i`, which used to take one constant-time
`Group.exp` per share. Since both the shares and the coefficients are public,
the product now goes through `Group.multiExpPublic`, which the elliptic backends
implement by noble's variable-time multiplication for fewer than 4 shares and by
Pippenger's bucket method from 4 shares on. Pippenger's method shares one chain
of doublings among all shares, whereas the multiplications cannot gain much on
their own: the coefficients are full-width scalars, unlike the share indexes of
[Horner's method](#variable-time-steps-in-commitment-verification). On `secp256k1`, single variable-time
multiplications already use the curve's endomorphism, so Pippenger's method takes
over only from 16 shares on; the thresholds are the crossovers measured with
`@noble/curves` 2.4.0 on every supported curve. Moreover, `recoverPublic` parsed
the public share of every packet twice, when verifying and when combining, and
now keeps the point it verified. Measured with `n = 100` shares:

| operation | threshold | `ed25519` | `decaf448` | `secp256k1` | `p521` |
| --- | ---: | ---: | ---: | ---: | ---: |
| `combinePublicShares` | 5 | -13% | -16% | -59% | -36% |
| `combinePublicShares` | 25 | -32% | -51% | -69% | -65% |
| `combinePublicShares` | 50 | -37% | -59% | -76% | -72% |
| `combinePublicShares` | 100 | -35% | -57% | -80% | -78% |
| `recoverPublic` | 5-100 | -29% to -31% | -21% to -22% | -38% to -40% | -37% to -41% |

For example, combining 25 public shares on `secp256k1` takes 14.4 ms instead of
46.5 ms. The gain is smaller on `ed25519`, where parsing a share costs about as
much as raising it to its coefficient used to: its check of membership in the
prime-order subgroup is a full multiplication, which remains, and dominates
after the change. `recoverPublic` costs the same at every threshold, since it
combines all valid packets, here 100, and the verification of their NIZK proofs,
which used `Group.exp` at the time, makes up most of its time (see
[NIZK verification](#nizk-verification)). Of its gain, parsing once accounts
for about half on `ed25519`, a quarter on `decaf448` and little on the curves of
cofactor one, where parsing is cheap.

## Generator of decaf448

On the cofactored curves, noble blinds multiplication only for its own base
point, which it recognizes by identity. The base point of `decaf448` is
represented by twice the base point of `ed448`, but as another object, so that
noble blinded none of its multiplications, and every exponentiation by a secret
scalar on `decaf448` took the [split](./SECURITY.md#exponentiation-by-secret-scalars).
The elliptic backend now computes `g^s` on `decaf448` as twice `B^s`, where `B` is the base
point of `ed448`, whose multiplication noble blinds and accelerates by a
precomputed table. Both groups have the same prime order, and doubling the
result avoids any arithmetic on the secret scalar. Exponentiations of other
points still split. Verification gains as well where it raises the generator:
to the share value in VSS verification, through `Group.expSecret`, which no
longer splits, and to the public NIZK response in Schnorr packets, through
`Group.exp`, which took the same route (verification has since moved to
`Group.multiExpPublic`, see [NIZK verification](#nizk-verification)). Measured
on `decaf448` with `n = 5` shares and threshold `t = 3`:

| operation | change |
| --- | ---: |
| `randomSecret`, `extractPublic` | -86% |
| `getPublicShares`, `createFeldmanPackets` | -86% |
| `createSchnorrPacket` | -80% |
| `createPedersenPackets` | -44% |
| verify/parse Feldman packets | -72% |
| verify/parse Pedersen packets | -40% |
| `parseSchnorrPacket` | -33% |
| `recoverPublic` | -23% |

For example, extracting a public key takes 0.60 ms instead of 4.23 ms, against
0.44 ms on `ed448`. Pedersen operations gain less, since exponentiations of
the Pedersen base still split. The other curves are unchanged.

## Pedersen base table

Pedersen dealing raises the Pedersen base `h` to the coefficients of the binding
polynomial, and verification to the binding of the share, all secret scalars.
Every operation used to parse `h` from its encoding and multiply it without a
precomputed table. Vsslib now keeps up to 8 parsed bases, evicting the least
recently used, and passes a base through `Group.precomputeBase` on its second
use, which the elliptic backends implement by attaching a noble table of window
4 to the point. The limit applies per backend class, so that the built-in
curves share it. Only bases that pass validation are kept, so invalid ones are
rejected on every call. On the curves of cofactor one, noble blinds every
multiplication and the blinded multiplication uses the table as well, so that
the whole exponentiation of `h` becomes 4 to 4.5 times faster. On the
cofactored curves, only the first multiplication of the
[split](./SECURITY.md#exponentiation-by-secret-scalars) can use the table, since the second
one runs on a fresh point, and the exponentiation of `h` becomes 30% to 37%
faster. Measured reusing the same base:

| operation | threshold | `ed25519` | `decaf448` | `secp256k1` | `p521` |
| --- | ---: | ---: | ---: | ---: | ---: |
| `createPedersenPackets` | 3 / 10 | -38% / -32% | -31% / -28% | -62% / -62% | -65% / -65% |
| verify/parse Pedersen packets | 3 | -24% to -28% | -26% to -32% | -55% to -59% | -60% to -61% |
| verify/parse Pedersen packets | 10 | -11% to -13% | -18% to -19% | -42% | -48% to -49% |

For example, dealing Pedersen packets on `p521` with threshold 3 takes 9.5 ms
instead of 27.5 ms. Verification gains less at higher thresholds, since the
evaluation of the commitments grows with the threshold and does not involve
`h`. The number of shares does not matter. A base used once costs as before,
e.g. when a shareholder verifies a single packet under a per-session base,
since the first operation with a base only parses and keeps it. The second
builds the table, which costs a few untabled multiplications (5.9 against
0.9 ms on `ed25519`, 20.9 against 7.4 ms on `p521`): dealing at threshold 3
then takes about as long as before, and a single verification a few
milliseconds longer. The gain starts with the third use. Moreover, the first
tables built in a process run unoptimized code, a one-off of up to about 12 ms.
A table takes 107 KB on `secp256k1` to 315 KB on `p521`.

## NIZK verification

Verifying a NIZK proof checks, for each row of the relation, that the row's
commitment equals the product of its points raised to the responses and to the
negated challenge, e.g. one row for a Schnorr proof and two for a DDH proof. All
of these are public, yet the verification used the constant-time `Group.exp`.
It now computes each product by one `Group.multiExpPublic`, which below its
cutoff (4 points, 16 on `secp256k1`) multiplies each point in variable time,
using noble's table for the generator; on `decaf448`, the generator goes
through the table of the `ed448` base, as for secret scalars (see
[Generator of decaf448](#generator-of-decaf448)). Moreover, the commitments of the
proofs are no longer checked for membership in the prime-order subgroup, which
costs a full multiplication on `ed25519`, `ed448` and `jubjub` (see
[Input validation](./SECURITY.md#input-validation)). Every Schnorr packet goes
through this verification, so that it makes up most of `recoverPublic`.
Measured:

| operation | shares | `ed25519` | `ed448` | `decaf448` | `secp256k1` | `p521` |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `parseSchnorrPacket` | - | -32% | -25% | +6% | -51% | -24% |
| `recoverPublic` | 5 / 20 | -26% / -25% | -19% / -22% | +2% / +6% | -50% / -40% | -14% / -19% |
| `recoverPublic` | 100 | -32% | -27% to -29% | -1% to -2% | -49% to -50% | -22% to -27% |

For example, recovering the public key from 100 packets on `secp256k1` takes
134 ms instead of 261 ms. On `secp256k1` and `p521`, most of the gain comes from
variable-time multiplication, on `ed25519` and `ed448` from dropping the subgroup
check of the commitments. `decaf448` is unchanged to slightly slower: its
subgroup check is cheap, and the variable-time multiplications gain nothing
measurable in the verification as a whole.

## Measurement setup

The figures were measured with the [benchmarks](./README.md#benchmarks), 5 runs
per side, on an Intel Core i5-12450H pinned to its performance cores (`--cpus 0-7`) with
the `powersave` governor, under Ubuntu 24.04.5 (Linux 6.8), Node.js 22.22.1 and
`@noble/curves` 2.4.0. Absolute times depend on the machine; the relative
changes are what to compare. To reproduce, save baselines with `--save` before
the changes and compare after them. For Horner's method:

```
$ ./bench.sh -m shamir,feldman,pedersen -s ed25519,decaf448,secp256k1,p521 \
    -n 10,50 -t 5,25 --cpus 0-7 -r 5 --compare <baseline>
```

For the common denominator:

```
$ ./bench.sh -o "combine*,recoverPublic" -s ed25519,decaf448,secp256k1,p521 \
    -n 100 -t 5,25,50,100 --cpus 0-7 -r 5 --compare <baseline>
```

For multi-exponentiation, with `parseSchnorrPacket` as a control that should
not change:

```
$ ./bench.sh -o "combinePublicShares,recoverPublic,parseSchnorrPacket" \
    -s ed25519,decaf448,secp256k1,p521 -n 100 -t 5,25,50,100 --cpus 0-7 -r 5 \
    --compare <baseline>
```

For the generator of `decaf448`, with `ed448` as a control that should not
change:

```
$ ./bench.sh -m secrets,shamir,feldman,pedersen,recovery -s decaf448,ed448 \
    --cpus 0-7 -r 5 --compare <baseline>
```

For the Pedersen base table, with the Feldman operations as a control that
should not change, and `verifyPedersenNewBase` measuring the first use of a
base:

```
$ ./bench.sh -m pedersen,feldman -s ed25519,decaf448,secp256k1,p521 \
    -n 5,20 -t 3,10 --cpus 0-7 -r 5 --compare <baseline>
```

For NIZK verification, with `createSchnorrPacket` as a control that should not
change:

```
$ ./bench.sh -m recovery -s ed25519,ed448,decaf448,secp256k1,p521 -n 5,20 -t 3 \
    --cpus 0-7 -r 5 --compare <baseline>
$ ./bench.sh -o recoverPublic -s ed25519,ed448,decaf448,secp256k1,p521 -n 100 \
    -t 5,50 --cpus 0-7 -r 5 --compare <baseline>
```
