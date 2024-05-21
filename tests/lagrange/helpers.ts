import { BasePolynomial } from '../../src/lagrange/utils';
import { XYPoint } from '../../src/lagrange/core';
import { modInv } from '../../src/arith';

const __0n = BigInt(0);
const __1n = BigInt(1);


/** Textbook lagrange interpolation */
export const interpolate = (points: XYPoint[], order: bigint): BasePolynomial => {
  const xys = points.map(([x, y]) => [BigInt(x), BigInt(y)]);
  let poly = BasePolynomial.zero({ order });
  for (let j = 0; j < xys.length; j++) {
    const [xj, yj] = xys[j];
    let w = __1n;
    let pj = new BasePolynomial([__1n], order);
    for (let i = 0; i < xys.length; i++) {
      if (i !== j) {
        const [xi, _] = xys[i];
        w *= xj - xi;
        pj = pj.mult(new BasePolynomial([-xi, __1n], order))
      }
    }
    const wInv = modInv(w, order);
    pj = pj.multScalar(yj * wInv)
    poly = poly.add(pj);
  }

  return poly;
}
