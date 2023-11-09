import { Messages } from './enums';
import { byteLen, randBigint } from '../utils';
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

export const randomPolynomial = async (opts: { degree: number, label: Label }): Promise<Polynomial<Point>> => {
  const { degree, label } = opts;
  const ctx = backend.initGroup(label);
  const { order } = ctx;
  if (degree < 0) throw new Error(Messages.DEGREE_MUST_BE_GE_ZERO)
  const coeffs = new Array(degree + 1);
  const nrBytes = byteLen(order);
  for (let i = 0; i < coeffs.length; i++) {
    coeffs[i] = await randBigint(nrBytes);
  }
  return new Polynomial(ctx, coeffs);
}
