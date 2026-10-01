import { describe } from 'node:test';
import assert from 'node:assert/strict';
import { each } from '../utils';
import { initBackend } from 'vsslib/backend';
import { FieldPolynomial, randomPolynomial } from 'vsslib/polynomials';
import { cartesian } from '../utils';
import { resolveTestConfig } from '../environ';


const __0n = BigInt(0);
const { systems } = resolveTestConfig();


describe('Random polynomial generation', () => {
  each(systems)('Non-positive degree error - over %s', async (system) => {
    const ctx = initBackend(system);
    await assert.rejects(randomPolynomial(ctx, -1), /Polynomial degree must be positive/);
  });
  each(systems)('Success - over %s', async (system) => {
    const ctx = initBackend(system);
    const degree = 7;
    const polynomial = await randomPolynomial(ctx, degree);
    assert.equal(polynomial.ctx.system, system);
    assert.deepEqual(polynomial.degree, degree);
    assert.deepEqual(polynomial.coeffs.length, degree + 1);
  });
});


describe('Algebraic operations with random poynomials', () => {
  const degree_pairs = [
    [0, 0], [0, 1], [1, 1], [0, 2], [1, 2], [2, 2], [5, 7], [6, 9], [7, 9], [8, 9]
  ];

  each(cartesian([degree_pairs, systems]))('Addition - degrees %s over %s', async (
    degrees, system
  ) => {
    const ctx = initBackend(system);
    const [degree1, degree2] = degrees.sort((a: number, b: number) => a - b);
    const poly1 = await randomPolynomial(ctx, degree1);
    const poly2 = await randomPolynomial(ctx, degree2);
    const poly3 = new FieldPolynomial(
      ctx,
      poly1.coeffs.map((c: bigint, i: number) => c + poly2.coeffs[i]).concat(
        poly2.coeffs.slice(poly1.degree + 1)
      ),
    );
    assert.equal(poly3.equals(poly1.add(poly2)), true);
    assert.equal(poly3.equals(poly2.add(poly1)), true);
  });

  each(cartesian([degree_pairs, systems]))('Multiplication - degrees %s over %s', async (
    degrees, system
  ) => {
    const ctx = initBackend(system);
    const [degree1, degree2] = degrees.sort((a: number, b: number) => a - b);
    const poly1 = await randomPolynomial(ctx, degree1);
    const poly2 = await randomPolynomial(ctx, degree2);
    const newCoeffs = new Array(degree1 + degree2 + 1).fill(__0n);
    for (let i = 0; i <= degree1; i++) {
      for (let j = 0; j <= degree2; j++) {
        newCoeffs[i + j] += poly1.coeffs[i] * poly2.coeffs[j];
      }
    }
    const poly3 = new FieldPolynomial(ctx, newCoeffs);
    assert.equal(poly3.equals(poly1.mult(poly2)), true);
    assert.equal(poly3.equals(poly2.mult(poly1)), true);
  });
});
