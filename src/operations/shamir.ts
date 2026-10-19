import { Point, Group } from '../backend';
import { mod } from '../arith';
import { FieldPolynomial } from '../polynomials';
import { InterpolationError, ShamirError, InvalidInput } from '../errors';
import { lagrange, computeLambda } from '../lagrange';
import { validateIndexes, validateShareCount } from '../indexes';
import { SecretShare, PublicShare } from '../types';


export class ShamirSharing<P extends Point> {
  ctx: Group<P>;
  nrShares: number;
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

  getOriginalSecret = (): Uint8Array => {
    return this.ctx.scalarToBytes(this.polynomial.evaluate(0n));
  }

  getSecretShares = async (): Promise<SecretShare[]> => {
    const polynomial = this.polynomial;
    const shares = new Array(this.nrShares);
    for (let index = 1; index <= this.nrShares; index++) {
      const value = this.ctx.scalarToBytes(polynomial.evaluate(index));
      shares[index - 1] = { value, index };
    }
    return shares;
  }

  getPublicShares = async (): Promise<PublicShare[]> => {
    const polynomial = this.polynomial;
    const shares = [];
    const g = this.ctx.generator;
    for (let index = 1; index <= this.nrShares; index++) {
      const x = polynomial.evaluate(index);
      const y = await this.ctx.exp(g, x);
      const value = y.toBytes();
      shares.push({ value, index });
    }
    return shares;
  }

  getShare = async (index: number): Promise<{
    secretShare: SecretShare,
    publicShare: PublicShare
  }> => {
    const g = this.ctx.generator;
    const x = await this.polynomial.evaluate(index);
    const y = await this.ctx.exp(g, x);
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


export async function shareSecret<P extends Point>(
  ctx: Group<P>,
  nrShares: number,
  threshold: number,
  secret?: Uint8Array,
  predefined?: SecretShare[],
): Promise<{ secret: Uint8Array, sharing: ShamirSharing<P>}> {
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
  const xyPoints = new Array(threshold);

  try {
    const scalarSecret = await ctx.parseScalar(secret);
    xyPoints[0] = [0n, scalarSecret];
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
  } catch (err: unknown) {
    if (err instanceof InvalidInput)
      throw new ShamirError(err.message);
    else
      throw err;
  }

  let polynomial;
  try {
    polynomial = await lagrange(ctx).interpolate(xyPoints);
  } catch (err: unknown) {
    if (err instanceof InterpolationError) throw new ShamirError(
      err.message
    );
    else throw err;
  }
  const sharing = new ShamirSharing(ctx, nrShares, threshold, polynomial);
  return { secret, sharing };
}


export async function combineSecretShares<P extends Point>(
  ctx: Group<P>,
  shares: SecretShare[],
  threshold: number,
): Promise<Uint8Array> {
  validateShareCount(shares.length, threshold);
  const order = ctx.order;
  const indexes = shares.map(share => share.index);
  validateIndexes(indexes);
  let x = 0n;
  for (const { value, index } of shares) {
    const li = computeLambda(ctx, index, indexes);
    const xi = await ctx.parseScalar(value);
    x = mod(x + li * xi, order);
  }
  return ctx.scalarToBytes(x);
}


export async function combinePublicShares<P extends Point>(
  ctx: Group<P>,
  shares: PublicShare[],
  threshold: number,
): Promise<Uint8Array> {
  validateShareCount(shares.length, threshold);
  const exp = ctx.exp;
  const indexes = shares.map(share => share.index);
  validateIndexes(indexes);
  let y = ctx.neutral;
  for (const { value, index } of shares) {
    const li = computeLambda(ctx, index, indexes);
    const yi = await ctx.parsePoint(value)
    y = await ctx.operate(y, await exp(yi, li));
  }
  return y.toBytes();
}
