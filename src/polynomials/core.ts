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

  async generateFeldmannCommitments(): Promise<{ commitments: P[] }> {
    const { coeffs, degree, ctx: { operate, generator }} = this;
    const commitments = new Array(degree + 1);
    for (const [index, coeff] of coeffs.entries()) {
      commitments[index] = await operate(coeff, generator);
    }
    return { commitments };
  }

  async generatePedersenCommitments(pub?: P): Promise<{ bindings: bigint[], pub: P, commitments: P[] }>{
    const { coeffs, degree, ctx: { generator: g, combine, operate }} = this;
    const bindingPolynomial = await Polynomial.random(this.ctx, degree);
    const commitments = new Array(degree + 1);
    const bindings = new Array(degree + 1);
    const h = pub || await this.ctx.randomPoint();
    for (const [i, a] of coeffs.entries()) {
      const b = bindingPolynomial.coeffs[i];
      commitments[i] = await combine(
        await operate(a, g),
        await operate(b, h),
      );
      bindings[i] = await bindingPolynomial.evaluate(i);
    }
    return { bindings, pub: h, commitments };
  }
}


export async function verifyFeldmannCommitments<P extends Point>(
  ctx: Group<P>,
  secret: bigint,
  index: number,
  commitments: P[],
): Promise<boolean> {
  const { order, generator, neutral, operate, combine } = ctx;
  const lhs = await operate(secret, generator);
  let rhs = neutral;
  const i = index;
  for (const [j, c] of commitments.entries()) {
    const curr = await operate(mod(BigInt(i ** j), order), c);
    rhs = await combine(rhs, curr);
  }
  return await lhs.isEqual(rhs);
}


export async function verifyPedersenCommitments<P extends Point>(
  ctx: Group<P>,
  secret: bigint,
  binding: bigint,
  index: number,
  pub: P,
  commitments: P[],
): Promise<boolean> {
  const { order, generator: g, neutral, operate, combine } = ctx;
  const lhs = await combine(await operate(secret, g), await operate(binding, pub));
  let rhs = neutral;
  const i = index;
  for (const [j, c] of commitments.entries()) {
    rhs = await combine(rhs, await operate(BigInt(i ** j), c));
  }
  return await lhs.isEqual(rhs);
}
