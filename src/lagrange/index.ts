import { BasePolynomial } from './base';
import { XYPoint, Polynomial, Lagrange } from './core';

export {
  XYPoint,
  Lagrange,
  Polynomial,
  BasePolynomial,
}

export const interpolate = (points: XYPoint[], opts: { order: bigint | number }): Lagrange => {
  const order = BigInt(opts.order);
  return new Lagrange(points.map(([x, y]) => [BigInt(x), BigInt(y)]), order);
}
