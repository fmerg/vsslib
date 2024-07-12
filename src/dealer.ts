import { Point, Group } from 'vsslib/backend';
import { FieldPolynomial, randomPolynomial } from 'vsslib/polynomials';
import { InterpolationError, ShamirError, InvalidInput } from 'vsslib/errors';
import { leInt2Buff } from 'vsslib/arith';
import { validateSecret } from 'vsslib/secrets';

import lagrange from 'vsslib/lagrange';

const __0n = BigInt(0);
const __1n = BigInt(1);

export type SecretShare = { value: Uint8Array, index: number };
export type SecretPacket = SecretShare & { binding?: Uint8Array };

export type PublicShare = { value: Uint8Array, index: number };


export class ShamirSharing<P extends Point> {
  ctx: Group<P>;
  nrShares: number;
  threshold: number;
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
    return leInt2Buff(this.polynomial.evaluate(__0n));
  }

  getSecretShares = async (): Promise<SecretShare[]> => {
    const polynomial = this.polynomial;
    const shares = new Array(this.nrShares);
    for (let index = 1; index <= this.nrShares; index++) {
      const value = leInt2Buff(polynomial.evaluate(index));
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
        value: leInt2Buff(x),
        index,
      },
      publicShare: {
        value: y.toBytes(),
        index,
      }
    };
  }

  createFeldmanPackets = async (): Promise<{
    packets: SecretPacket[],
    commitments: Uint8Array[],
  }> => {
    const { exp, generator: g } = this.ctx;
    const { coeffs, degree, evaluate } = this.polynomial;
    const commitments = new Array(degree + 1);
    const packets = new Array<SecretPacket>(this.nrShares);
    for (let i = 0; i < this.nrShares; i++) {
      if (i < degree + 1) {
        const c = await exp(g, coeffs[i]);
        commitments[i] = c.toBytes();
      }
      const index = i + 1;
      const value = leInt2Buff(evaluate(index));
      packets[i] = { value, index };
    }
    return { packets, commitments };
  }

  createPedersenPackets = async (publicBytes: Uint8Array): Promise<{
    packets: SecretPacket[],
    bindings: Uint8Array[],
    commitments: Uint8Array[],
  }> => {
    const polynomial = this.polynomial;
    const degree = polynomial.degree;
    const g = this.ctx.generator;
    const h = await this.ctx.unpackValid(publicBytes);
    const exp = this.ctx.exp;
    const commitments = new Array(degree + 1);
    const bindings = new Array(degree + 1);
    const packets = new Array<SecretPacket>(this.nrShares);
    const bindingPolynomial = await randomPolynomial(this.ctx, degree);
    for (let i = 0; i < this.nrShares; i++) {
      if (i < degree + 1) {
        const a = polynomial.coeffs[i];
        const b = bindingPolynomial.coeffs[i];
        const c = await this.ctx.operate(
          await exp(g, a),
          await exp(h, b),
        );
        commitments[i] = c.toBytes();
      }
      const index = i + 1;
      const x = polynomial.evaluate(index);
      const s = bindingPolynomial.evaluate(index)
      const value = leInt2Buff(x);
      const binding = leInt2Buff(s);
      bindings[i] = binding;
      packets[i] = { value, index, binding };
    }
    return { packets, bindings, commitments };
  }
};


export async function distributeSecret<P extends Point>(
  ctx: Group<P>, nrShares: number, threshold: number, secret?: Uint8Array, predefined?: Uint8Array[]
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

  secret = secret || await ctx.randomSecret()
  try {
    await validateSecret(ctx, secret);
  } catch (err: any) {
    if (err instanceof InvalidInput)
      throw new ShamirError(err.message);
    else
      throw err;
  }
  const xyPoints = new Array(threshold);
  xyPoints[0] = [__0n, ctx.leBuff2Scalar(secret)];
  let index = 1;
  while (index < threshold) {
    const x = index;
    const y = index > predefined.length ? await ctx.randomScalar() :
      ctx.leBuff2Scalar(predefined[index - 1]);
    xyPoints[index] = [x, y];
    index++;
  }

  let polynomial;
  try {
    polynomial = await lagrange(ctx).interpolate(xyPoints);
  } catch (err: any) {
    if (err instanceof InterpolationError) throw new ShamirError(
      err.message
    );
    else throw err;
  }
  const sharing = new ShamirSharing(ctx, nrShares, threshold, polynomial);
  return { secret, sharing };
}
