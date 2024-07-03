import { Point, Group } from 'vsslib/backend';
import { PolynomialEerror } from 'vsslib/errors';
import { BasePolynomial } from './base';


export class FieldPolynomial<P extends Point> extends BasePolynomial {
  ctx: Group<P>;
  constructor(ctx: Group<P>, coeffs: bigint[]) {
    super(coeffs, ctx.order);
    this.ctx = ctx;
  }
}


export async function randomPolynomial<P extends Point>(ctx: Group<P>, degree: number) {
  if (degree < 0) throw new PolynomialEerror(
    `Polynomial degree must be positive: ${degree}`
  );
  const { randomScalar } = ctx;
  const coeffs = new Array(degree + 1);
  for (let i = 0; i < coeffs.length; i++) {
    coeffs[i] = await randomScalar();
  }
  return new FieldPolynomial(ctx, coeffs);
}
