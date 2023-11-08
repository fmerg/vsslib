import { Label } from '../types';
import { Point } from '../backend/abstract'
import { BasePolynomial } from './base';
import { XYPoint, Polynomial, Lagrange } from './core';

const backend = require('../backend');

export {
  XYPoint,
  Lagrange,
  Polynomial,
  BasePolynomial,
}

export const interpolate = (points: XYPoint[], opts: { label: Label }): Lagrange<Point> => {
  const ctx = backend.initGroup(opts.label);
  return new Lagrange(ctx, points.map(([x, y]) => [BigInt(x), BigInt(y)]));
}
