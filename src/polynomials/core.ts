import { Point, Group } from '../backend/abstract';
import { BasePolynomial } from './base';
import { Messages } from './enums';


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
}
