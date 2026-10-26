import { Point, Group } from '../backend';
import { mod } from '../arith';
import { FieldPolynomial } from '../polynomials';
import { InterpolationError, ShamirError, InvalidInput } from '../errors';
import { lagrange, computeLambdas } from '../lagrange';
import { validateIndexes, validateShareCount } from '../indexes';
import { SecretShare, PublicShare } from '../types';


/** A `(nrShares, threshold)`-sharing of a secret, created by
 * {@link shareSecret}. It holds the secret, so drop it once the shares are
 * distributed */
export class ShamirSharing<P extends Point> {
  /** Group of the sharing */
  ctx: Group<P>;
  /** Number of shares, at indexes 1 to `nrShares` */
  nrShares: number;
  /** Number of shares that recover the secret */
  threshold: number;
  /** @internal Sharing polynomial, read by the VSS schemes */
  polynomial: FieldPolynomial<P>;

  constructor(
    ctx: Group<P>, nrShares: number, threshold: number, polynomial: FieldPolynomial<P>
  ) {
    this.ctx = ctx;
    this.threshold = threshold;
    this.nrShares = nrShares;
    this.polynomial = polynomial;
  }

  /** The shared secret */
  getOriginalSecret = (): Uint8Array => {
    return this.ctx.scalarToBytes(this.polynomial.evaluate(0n));
  }

  /** All secret shares, in the order of their indexes */
  getSecretShares = async (): Promise<SecretShare[]> => {
    const polynomial = this.polynomial;
    const shares = new Array(this.nrShares);
    for (let index = 1; index <= this.nrShares; index++) {
      const value = this.ctx.scalarToBytes(polynomial.evaluate(index));
      shares[index - 1] = { value, index };
    }
    return shares;
  }

  /** All public shares, in the order of their indexes */
  getPublicShares = async (): Promise<PublicShare[]> => {
    const polynomial = this.polynomial;
    const shares = [];
    const g = this.ctx.generator;
    for (let index = 1; index <= this.nrShares; index++) {
      const x = polynomial.evaluate(index);
      const y = await this.ctx.expSecret(g, x);
      const value = y.toBytes();
      shares.push({ value, index });
    }
    return shares;
  }

  /** Secret and public share at `index` */
  getShare = async (index: number): Promise<{
    /** Share at `index` */
    secretShare: SecretShare,
    /** Its public counterpart */
    publicShare: PublicShare,
  }> => {
    const g = this.ctx.generator;
    const x = await this.polynomial.evaluate(index);
    const y = await this.ctx.expSecret(g, x);
    return {
      secretShare: {
        value: this.ctx.scalarToBytes(x),
        index,
      },
      publicShare: {
        value: y.toBytes(),
        index,
      }
    };
  }
};


/** @internal Polynomial of degree < threshold with the secret as constant term and
 * uniform other coefficients */
export async function sampleSharingPolynomial<P extends Point>(
  ctx: Group<P>,
  threshold: number,
  secret: bigint,
): Promise<FieldPolynomial<P>> {
  const coeffs = new Array(threshold);
  coeffs[0] = secret;
  // PERFORMANCE! coefficients sampled directly instead of interpolated
  for (let i = 1; i < threshold; i++) coeffs[i] = await ctx.randomScalar();
  return new FieldPolynomial(ctx, coeffs);
}


/** @internal Polynomial of degree < threshold through (0, secret), the predefined shares
 * and uniform values at the remaining indexes below threshold; with no
 * predefined shares it has the distribution of sampleSharingPolynomial.
 * Throws if threshold - 1 predefined shares lie with the secret on a polynomial
 * of lower degree, which fewer than threshold shares would recover */
export async function interpolateSharingPolynomial<P extends Point>(
  ctx: Group<P>,
  threshold: number,
  secret: bigint,
  predefined: SecretShare[],
): Promise<FieldPolynomial<P>> {
  const xyPoints = new Array(threshold);
  xyPoints[0] = [0n, secret];
  // Allocate predefined shares
  for (const { index } of predefined) {
    if (!(0 < index && index < threshold)) {
      throw new InvalidInput(`Index not in range: ${index}`);
    }
  }
  validateIndexes(predefined.map(share => share.index));
  for (const { index, value } of predefined) {
    const x = index;
    const y = await ctx.parseScalar(value);
    xyPoints[index] = [x, y];
  }
  // Fill positions with non-predefined shares
  let index = 1;
  while (index < threshold) {
    if (xyPoints[index] == undefined) {
      const x = index;
      const y = await ctx.randomScalar();
      xyPoints[index] = [x, y];
    }
    index++;
  }
  const polynomial = await lagrange(ctx).interpolate(xyPoints);
  // No point was random, so the degree is fixed by the input
  if (predefined.length === threshold - 1 && polynomial.degree < threshold - 1) {
    const lower = polynomial.isZero() ? 'the zero polynomial' : `a polynomial of degree ${polynomial.degree}`;
    throw new InvalidInput(
      `Predefined shares and secret lie on ${lower}, below degree ${threshold - 1}`
    );
  }
  return polynomial;
}


/** Share a secret, freshly generated unless given, such that any `threshold`
 * of the `nrShares` shares recover it and fewer reveal nothing about it.
 * Up to `threshold - 1` predefined shares, at indexes below `threshold`, are
 * kept as given. Throws ShamirError unless `1 <= threshold <= nrShares < order`,
 * on invalid predefined shares, and if `threshold - 1` predefined shares lie
 * with the secret on a polynomial of lower degree; throws InvalidInput on an
 * invalid secret */
export async function shareSecret<P extends Point>(
  ctx: Group<P>,
  nrShares: number,
  threshold: number,
  secret?: Uint8Array,
  predefined?: SecretShare[],
): Promise<{
  /** The shared secret */
  secret: Uint8Array,
  /** The sharing, from which shares and VSS packets are taken */
  sharing: ShamirSharing<P>,
}> {
  predefined = predefined || [];
  if (nrShares < 1) throw new ShamirError(
    `Number of shares must be at least one: ${nrShares}`
  );
  if (threshold < 1) throw new ShamirError(
    `Threshold parameter must be at least 1: ${threshold}`
  );
  if (threshold > nrShares) throw new ShamirError(
    `Threshold parameter exceeds number of shares: ${threshold} > ${nrShares}`
  );
  if (!(nrShares < ctx.order)) throw new ShamirError(
    `Number of shares violates the group order: ${nrShares} >= ${ctx.order}`
  );
  if (!(predefined.length < threshold)) throw new ShamirError(
    `Number of predefined shares violates threshold: ${predefined.length} >= ${threshold}`,
  );

  secret = secret || await ctx.generateSecret()
  let polynomial;
  try {
    const scalarSecret = await ctx.parseScalar(secret);
    polynomial = predefined.length == 0 ?
      await sampleSharingPolynomial(ctx, threshold, scalarSecret) :
      await interpolateSharingPolynomial(ctx, threshold, scalarSecret, predefined);
  } catch (err: unknown) {
    if (err instanceof InvalidInput || err instanceof InterpolationError)
      throw new ShamirError(err.message);
    else
      throw err;
  }
  const sharing = new ShamirSharing(ctx, nrShares, threshold, polynomial);
  return { secret, sharing };
}


/** Secret recovered from at least `threshold` secret shares by interpolation
 * at zero; the shares are not verified. Throws InvalidInput on fewer shares,
 * invalid indexes or values */
export async function combineSecretShares<P extends Point>(
  ctx: Group<P>,
  shares: SecretShare[],
  threshold: number,
): Promise<Uint8Array> {
  validateShareCount(shares.length, threshold);
  const order = ctx.order;
  const lambdas = computeLambdas(ctx, shares.map(share => share.index));
  let x = 0n;
  for (let i = 0; i < shares.length; i++) {
    const xi = await ctx.parseScalar(shares[i].value);
    x = mod(x + lambdas[i] * xi, order);
  }
  return ctx.scalarToBytes(x);
}


/** Public counterpart of the secret, recovered from at least `threshold`
 * public shares by interpolation in the exponent; the shares are not verified
 * (see {@link recoverPublic}). Throws InvalidInput on fewer shares, invalid
 * indexes or values */
export async function combinePublicShares<P extends Point>(
  ctx: Group<P>,
  shares: PublicShare[],
  threshold: number,
): Promise<Uint8Array> {
  validateShareCount(shares.length, threshold);
  const lambdas = computeLambdas(ctx, shares.map(share => share.index));
  const points = [];
  for (const share of shares) points.push(await ctx.parsePoint(share.value));
  // PERFORMANCE! one multi-exponentiation instead of one per share
  // Shares and coefficients are public, so variable time is safe
  const y = await ctx.multiExpPublic(points, lambdas);
  return y.toBytes();
}
