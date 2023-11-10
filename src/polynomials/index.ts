import { Messages } from './enums';
import { byteLen, randBigint } from '../utils';
import { Label } from '../types';
import { Point } from '../backend/abstract'
import { BasePolynomial } from './base';
import { Polynomial } from './core';
import { LagrangePolynomial, XYPoint } from './lagrange';

const backend = require('../backend');
const lagrange = require('./lagrange');

export {
  XYPoint,
  LagrangePolynomial,
  Polynomial,
  BasePolynomial,
  lagrange,
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
