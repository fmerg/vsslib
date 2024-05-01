import { Group, Point } from './backend/abstract';
import { FieldPolynomial, randomPolynomial } from './lagrange';


export interface BaseShare<T> {
  value: T;
  index: number;
}


export abstract class BaseSharing<
  S, P extends Point, Q extends BaseShare<S>, R extends BaseShare<P>
> {
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

  abstract getSecretShares: () => Promise<Q[]>;
  abstract getPublicShares: () => Promise<R[]>;

  proveFeldmann = async (): Promise<{ commitments: P[] }> => {
    const { coeffs, degree, ctx: { operate, generator }} = this.polynomial;
    const commitments = new Array(degree + 1);
    for (const [index, coeff] of coeffs.entries()) {
      commitments[index] = await operate(coeff, generator);
    }
    return { commitments };
  }

  provePedersen = async (hPub?: P): Promise<{
    bindings: bigint[],
    hPub: P,
    commitments: P[],
  }> => {
    const { generator: g, combine, operate } = this.ctx;
    const { coeffs, degree } = this.polynomial;
    const bindingPolynomial = await randomPolynomial(this.ctx, degree);
    const commitments = new Array(degree + 1);
    const bindings = new Array(degree + 1);
    hPub = hPub || await this.ctx.randomPoint();
    for (const [i, a] of coeffs.entries()) {
      const a = coeffs[i];
      const b = bindingPolynomial.coeffs[i];
      commitments[i] = await combine(
        await operate(a, g),
        await operate(b, hPub),
      );
      bindings[i] = await bindingPolynomial.evaluate(i);
    }
    for (let j = coeffs.length; j <= this.nrShares; j++) {
      bindings[j] = await bindingPolynomial.evaluate(j);
    }
    return { bindings, hPub, commitments };
  }
}
