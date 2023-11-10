import { Point, Group } from '../backend/abstract';
import { BasePolynomial } from './base';
import { Messages } from './enums';
import { mod, modInv, Messages as utilMessages } from '../utils';


const __0n = BigInt(0);
const __1n = BigInt(1);


export class Polynomial<P extends Point> extends BasePolynomial {
  ctx: Group<P>;
  constructor(ctx: Group<P>, coeffs: bigint[]) {
    super(coeffs, ctx.order);
    this.ctx = ctx;
  }

  static async random<Q extends Point>(ctx: Group<Q>, degree: number): Promise<Polynomial<Q>> {
    if (degree < 0) throw new Error(Messages.DEGREE_MUST_BE_GE_ZERO)
    const { randomScalar } = ctx;
    const coeffs = new Array(degree + 1);
    for (let i = 0; i < coeffs.length; i++) {
      coeffs[i] = await randomScalar();
    }
    return new Polynomial(ctx, coeffs);
  }

  async generateFeldmannCommitments(): Promise<P[]> {
    const { coeffs, degree, ctx: { operate, generator }} = this;
    const commitments = new Array(degree + 1);
    for (const [index, coeff] of coeffs.entries()) {
      commitments[index] = await operate(coeff, generator);
    }
    return commitments;
  }

  async generatePedersenCommitments(h: P): Promise<{ commitments: P[], bs: bigint[] }>{
    const { coeffs, degree, ctx: { generator: g, combine, operate }} = this;
    const polynomial2 = await Polynomial.random(this.ctx, degree);
    const commitments = new Array(degree + 1);
    const bs = new Array(degree + 1);
    for (const [i, a] of coeffs.entries()) {
      const b = polynomial2.coeffs[i];
      commitments[i] = await combine(
        await operate(a, g),
        await operate(b, h),
      );
      bs[i] = await polynomial2.evaluate(i);
    }
    return { bs, commitments };
  }
}


export async function verifyFeldmannCommitments<P extends Point>(
  ctx: Group<P>,
  secret: bigint,
  index: number,
  commitments: P[],
): Promise<boolean> {
  const { order, generator, neutral, operate, combine } = ctx;
  const target = await operate(secret, generator);
  let acc = neutral;
  const i = index;
  for (const [j, comm] of commitments.entries()) {
    const curr = await operate(mod(BigInt(i ** j), order), comm);
    acc = await combine(acc, curr);
  }
  return await acc.isEqual(target);
}


export async function verifyPedersenCommitments<P extends Point>(
  ctx: Group<P>,
  secret: bigint,
  index: number,
  b: bigint,
  h: P,
  commitments: P[],
): Promise<boolean> {
  const { order, generator: g, neutral, operate, combine } = ctx;
  const lhs = await combine(
    await operate(secret, g),
    await operate(b, h),
  );
  let rhs = neutral;
  const i = index;
  for (const [j, c] of commitments.entries()) {
    rhs = await combine(rhs, await operate(BigInt(i ** j), c));
  }
  return await lhs.isEqual(rhs);
}
