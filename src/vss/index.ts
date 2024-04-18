import { Group, Point } from '../backend/abstract';
import { Polynomial } from '../core/lagrange';
import { mod, modInv, Messages as utilMessages } from '../utils';


export interface BaseShare<T> {
  value: T;
  index: number;
}


export abstract class BaseSharing<
  S,
  P extends Point,
  Q extends BaseShare<S>,
  R extends BaseShare<P>
> {
  ctx: Group<P>;
  nrShares: number;
  threshold: number;
  polynomial: Polynomial<P>;

  constructor(
    ctx: Group<P>, nrShares: number, threshold: number, polynomial: Polynomial<P>
  ) {
    this.ctx = ctx;
    this.threshold = threshold;
    this.nrShares = nrShares;
    this.polynomial = polynomial;
  }

  abstract getSecretShares: () => Promise<Q[]>;
  abstract getPublicShares: () => Promise<R[]>;

  getFeldmann = async (): Promise<{ commitments: P[] }> => {
    const { coeffs, degree, ctx: { operate, generator }} = this.polynomial;
    const commitments = new Array(degree + 1);
    for (const [index, coeff] of coeffs.entries()) {
      commitments[index] = await operate(coeff, generator);
    }
    return { commitments };
  }

  getPedersen = async (hPub?: P): Promise<{
    bindings: bigint[],
    hPub: P,
    commitments: P[],
  }> => {
    const { coeffs, degree, ctx: { generator: g, combine, operate }} = this.polynomial;
    const bindingPolynomial = await Polynomial.random(this.ctx, degree);
    const commitments = new Array(degree + 1);
    const bindings = new Array(degree + 1);
    const h = hPub || await this.ctx.randomPoint();
    for (const [i, a] of coeffs.entries()) {
      const a = coeffs[i];
      const b = bindingPolynomial.coeffs[i];
      commitments[i] = await combine(
        await operate(a, g),
        await operate(b, h),
      );
      bindings[i] = await bindingPolynomial.evaluate(i);
    }
    for (let j = coeffs.length; j <= this.nrShares; j++) {
      bindings[j] = await bindingPolynomial.evaluate(j);
    }
    return { bindings, hPub: h, commitments };
  }
}


export async function verifyFeldmann<P extends Point>(
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
  return await lhs.equals(rhs);
}


export async function verifyPedersen<P extends Point>(
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
  return await lhs.equals(rhs);
}
