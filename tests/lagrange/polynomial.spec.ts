import { initGroup } from '../../src/backend';
import { Polynomial } from '../../src/lagrange';
import { ErrorMessages } from '../../src/errors';
import { cartesian } from '../helpers';
import { resolveTestConfig } from '../environ';


const __0n = BigInt(0);
const __1n = BigInt(1);
const { systems } = resolveTestConfig();


describe('Random polynomial generation', () => {
  test('Non-positive degree error', async () => {
    const ctx = initGroup('ed25519');
    await expect(Polynomial.random(ctx, -1)).rejects.toThrow(
      ErrorMessages.NON_POSITIVE_DEGREE
    );
  });
  test('Correct parameters', async () => {
    const ctx = initGroup('ed25519');
    const degree = 7;
    const polynomial = await Polynomial.random(ctx, degree);
    expect(await polynomial.ctx.equals(ctx)).toBe(true);
    expect(polynomial.degree).toEqual(degree);
    expect(polynomial.coeffs.length).toEqual(degree + 1);
  });
});


describe('Algebraic operations with random poynomials', () => {
  const degree_pairs = [
    [0, 0], [0, 1], [1, 1], [0, 2], [1, 2], [2, 2], [5, 7], [6, 9], [7, 9], [8, 9]
  ];

  it.each(cartesian([degree_pairs, systems]))('Addition with degrees %s over %s', async (
    degrees, system
  ) => {
    const ctx = initGroup(system);
    let [degree1, degree2] = degrees.sort((a: number, b: number) => a - b);
    const poly1 = await Polynomial.random(ctx, degree1);
    const poly2 = await Polynomial.random(ctx, degree2);
    const poly3 = new Polynomial(
      ctx,
      poly1.coeffs.map((c: bigint, i: number) => c + poly2.coeffs[i]).concat(
        poly2.coeffs.slice(poly1.degree + 1)
      ),
    );
    expect(poly3.equals(poly1.add(poly2))).toBe(true);
    expect(poly3.equals(poly2.add(poly1))).toBe(true);
  });

  it.each(cartesian([degree_pairs, systems]))('Multiplication with degrees %s over %s', async (
    degrees, system
  ) => {
    const ctx = initGroup(system);
    let [degree1, degree2] = degrees.sort((a: number, b: number) => a - b);
    const poly1 = await Polynomial.random(ctx, degree1);
    const poly2 = await Polynomial.random(ctx, degree2);
    let newCoeffs = new Array(degree1 + degree2 + 1).fill(__0n);
    for (let i = 0; i <= degree1; i++) {
      for (let j = 0; j <= degree2; j++) {
        newCoeffs[i + j] += poly1.coeffs[i] * poly2.coeffs[j];
      }
    }
    const poly3 = new Polynomial(ctx, newCoeffs);
    expect(poly3.equals(poly1.mult(poly2))).toBe(true);
    expect(poly3.equals(poly2.mult(poly1))).toBe(true);
  });
});
