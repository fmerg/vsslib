import { backend } from '../src';
import { Systems } from '../src/enums';
import { Polynomial, verifyFeldmannCommitments } from '../src/lagrange/core';
import { Messages } from '../src/lagrange/enums';
import { byteLen, randBigint } from '../src/utils';
import { cartesian } from './helpers';
const lagrange = require('../src/lagrange');


const __0n = BigInt(0);
const __1n = BigInt(1);
const __labels = Object.values(Systems);


describe('construction', () => {
  it.each(__labels)('%s', async (label) => {
    const ctx = backend.initGroup(label);
    const coeffs = [];
    for (let i = 0; i < 5; i++) {
      coeffs.push(await ctx.randomScalar());
    }
    const polynomial = new Polynomial(ctx, coeffs);
  });
});



describe('Feldmann commitments', () => {
  const degrees = [0, 1, 2, 3, 4, 5];
  it.each(cartesian([__labels, degrees]))('degree %s over %s', async (label, degree) => {
    const ctx = backend.initGroup(label);
    const polynomial = await lagrange.randomPolynomial({ degree, label });
    const commitments = await polynomial.generateFeldmannCommitments();
    for (const [index, _] of polynomial.coeffs.entries()) {
      const secret = await polynomial.evaluate(index);
      const isValid = await verifyFeldmannCommitments(
        ctx,
        secret,
        index,
        commitments,
      );
      expect(isValid).toBe(true);
    }
  });
});


describe('Pedersen commitments', () => {
  it.each(__labels)('%s', async (label) => {
    const ctx = backend.initGroup(label);
  });
});


describe('random polynomial error', () => {
  test('non-positive degree', async () => {
    await expect(lagrange.randomPolynomial({ degree: -1, label: 'ed25519' })).rejects.toThrow(
      Messages.DEGREE_MUST_BE_GE_ZERO
    );
  });
});


describe('addition - random polynomials', () => {
  const degree_pairs = [
    [0, 0], [0, 1], [1, 1], [0, 2], [1, 2], [2, 2], [5, 7], [6, 9], [7, 9], [8, 9]
  ];
  it.each(cartesian([degree_pairs, __labels]))('degrees: %s over: %s', async (
    degrees, label
  ) => {
    const ctx = backend.initGroup(label);
    let [degree1, degree2] = degrees.sort((a: number, b: number) => a - b);
    const poly1 = await lagrange.randomPolynomial({ degree: degree1, label });
    const poly2 = await lagrange.randomPolynomial({ degree: degree2, label });
    const poly3 = new Polynomial(
      ctx,
      poly1.coeffs.map((c: bigint, i: number) => c + poly2.coeffs[i]).concat(
        poly2.coeffs.slice(poly1.degree + 1)
      ),
    );
    expect(poly3.isEqual(poly1.add(poly2))).toBe(true);
    expect(poly3.isEqual(poly2.add(poly1))).toBe(true);
  });
});


describe('multiplication - random polynomials', () => {
  const degree_pairs = [
    [0, 0], [0, 1], [1, 1], [0, 2], [1, 2], [2, 2], [5, 7], [6, 9], [7, 9], [8, 9]
  ];
  it.each(cartesian([degree_pairs, __labels]))('degrees: %s over: %s', async (
    degrees, label
  ) => {
    const ctx = backend.initGroup(label);
    let [degree1, degree2] = degrees.sort((a: number, b: number) => a - b);
    const poly1 = await lagrange.randomPolynomial({ degree: degree1, label });
    const poly2 = await lagrange.randomPolynomial({ degree: degree2, label });
    let newCoeffs = new Array(degree1 + degree2 + 1).fill(__0n);
    for (let i = 0; i <= degree1; i++) {
      for (let j = 0; j <= degree2; j++) {
        newCoeffs[i + j] += poly1.coeffs[i] * poly2.coeffs[j];
      }
    }
    const poly3 = new Polynomial(ctx, newCoeffs);
    expect(poly3.isEqual(poly1.mult(poly2))).toBe(true);
    expect(poly3.isEqual(poly2.mult(poly1))).toBe(true);
  });
});
