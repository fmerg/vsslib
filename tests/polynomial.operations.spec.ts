import { Systems } from '../src/enums';
import { Polynomial } from '../src/lagrange/base';
import { Messages } from '../src/lagrange/enums';
import { byteLen, randBigint } from '../src/utils';
import { cartesian } from './helpers';
const lagrange = require('../src/lagrange');
const backend = require('../src/backend');


const __0n = BigInt(0);
const __1n = BigInt(1);
const __small_orders = [2, 3, 4, 5, 6, 7];
const __big_primes = Object.values(Systems).map((label) => backend.initGroup(label).order);


describe('errors', () => {
  test('addition - different orders', async () => {
    const poly1 = new Polynomial([], 2);
    const poly2 = new Polynomial([], 3);
    expect(() => poly1.add(poly2)).toThrow(
      Messages.DIFFERENT_ORDERS_CANNOT_ADD
    );
  });
  test('multiplication - different orders', async () => {
    const poly1 = new Polynomial([], 2);
    const poly2 = new Polynomial([], 3);
    expect(() => poly1.mult(poly2)).toThrow(
      Messages.DIFFERENT_ORDERS_CANNOT_MULTIPLY
    );
  });
});


describe('addition - fixed polynomials small small order', () => {
  it.each(cartesian([
    [
      [[1, 2, 3, 4], [],                    [1, 2, 3, 4]],
      [[1, 2, 3, 4], [1],                   [2, 2, 3, 4]],
      [[1, 2, 3, 4], [1, 2],                [2, 4, 3, 4]],
      [[1, 2, 3, 4], [1, 2, 3],             [2, 4, 6, 4]],
      [[1, 2, 3, 4], [1, 2, 3, 4],          [2, 4, 6, 8]],
      [[1, 2, 3, 4], [1, 2, 3, 4, 5],       [2, 4, 6, 8, 5]],
      [[1, 2, 3, 4], [1, 2, 3, 4, 5, 6],    [2, 4, 6, 8, 5, 6]],
      [[1, 2, 3, 4], [1, 2, 3, 4, 5, 6, 7], [2, 4, 6, 8, 5, 6, 7]],
    ],
    __small_orders
  ]))('%s %s', async ([coeffs1, coeffs2, coeffs3], order) => {
    const poly1 = new Polynomial(coeffs1, order);
    const poly2 = new Polynomial(coeffs2.map((num: number) => num + order), order);
    const poly3 = new Polynomial(coeffs3, order);
    expect(poly3.isEqual(poly1.add(poly2))).toBe(true);
    expect(poly3.isEqual(poly2.add(poly1))).toBe(true);
  });
});


describe('addition - random polynomials with prime order', () => {
  const degree_pairs = [
    [0, 0], [0, 1], [1, 1], [0, 2], [1, 2], [2, 2], [5, 7], [6, 9], [7, 9], [8, 9]
  ];
  it.each(cartesian([degree_pairs, __big_primes]))('degrees: %s, order: %s', async (
    degrees, order
  ) => {
    let [degree1, degree2] = degrees.sort((a: number, b: number) => a - b);
    const poly1 = await Polynomial.random({ degree: degree1, order });
    const poly2 = await Polynomial.random({ degree: degree2, order });
    const poly3 = new Polynomial(
      poly1.coeffs.map((c, i) => c + poly2.coeffs[i]).concat(poly2.coeffs.slice(poly1.degree + 1)),
      order,
    );
    expect(poly3.isEqual(poly1.add(poly2))).toBe(true);
    expect(poly3.isEqual(poly2.add(poly1))).toBe(true);
  });
});


describe('multiplication - fixed polynomials small small order', () => {
  it.each(cartesian([
    [
      [[1, 2, 3, 4], [],                    []],
      [[1, 2, 3, 4], [1],                   [1, 2, 3, 4]],
      [[1, 2, 3, 4], [1, 2],                [1, 4, 7, 10, 8]],
      [[1, 2, 3, 4], [1, 2, 3],             [1, 4, 10, 16, 17, 12]],
      [[1, 2, 3, 4], [1, 2, 3, 4],          [1, 4, 10, 20, 25, 24, 16]],
      [[1, 2, 3, 4], [1, 2, 3, 4, 5],       [1, 4, 10, 20, 30, 34, 31, 20]],
      [[1, 2, 3, 4], [1, 2, 3, 4, 5, 6],    [1, 4, 10, 20, 30, 40, 43, 38, 24]],
      [[1, 2, 3, 4], [1, 2, 3, 4, 5, 6, 7], [1, 4, 10, 20, 30, 40, 50, 52, 45, 28]],
    ],
    __small_orders
  ]))('%s %s', async ([coeffs1, coeffs2, coeffs3], order) => {
    const poly1 = new Polynomial(coeffs1, order);
    const poly2 = new Polynomial(coeffs2.map((num: number) => num + order), order);
    const poly3 = new Polynomial(coeffs3, order);
    expect(poly3.isEqual(poly1.mult(poly2))).toBe(true);
    expect(poly3.isEqual(poly2.mult(poly1))).toBe(true);
  });
});


describe('multiplication - random polynomials with prime order', () => {
  const degree_pairs = [
    [0, 0], [0, 1], [1, 1], [0, 2], [1, 2], [2, 2], [5, 7], [6, 9], [7, 9], [8, 9]
  ];
  it.each(cartesian([degree_pairs, __big_primes]))('degrees: %s, order: %s', async (
    degrees, order
  ) => {
    let [degree1, degree2] = degrees;
    const poly1 = await Polynomial.random({ degree: degree1, order });
    const poly2 = await Polynomial.random({ degree: degree2, order });
    let newCoeffs = new Array(degree1 + degree2 + 1).fill(__0n);
    for (let i = 0; i <= degree1; i++) {
      for (let j = 0; j <= degree2; j++) {
        newCoeffs[i + j] += poly1.coeffs[i] * poly2.coeffs[j];
      }
    }
    const poly3 = new Polynomial(newCoeffs, order);
    expect(poly3.isEqual(poly1.mult(poly2))).toBe(true);
    expect(poly3.isEqual(poly2.mult(poly1))).toBe(true);
  });
});


describe('scalar multiplication - fixed polynomials small small order', () => {
  it.each(cartesian([
    [
      [],
      [1],
      [1, 2],
      [1, 2, 3],
      [1, 2, 3, 4],
      [1, 2, 3, 4, 5],
      [1, 2, 3, 4, 5, 6],
      [1, 2, 3, 4, 5, 6, 7],
    ],
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    __small_orders,
  ]))('%s %s, %s', async (coeffs, scalar, order) => {
    const poly1 = new Polynomial(coeffs, order);
    const poly2 = poly1.multScalar(scalar);

    const poly3 = new Polynomial(coeffs.map((c: number) => scalar * c), order);
    expect(poly2.isEqual(poly3)).toBe(true);

    const poly4 = new Polynomial([scalar], order);
    expect(poly2.isEqual(poly1.mult(poly4))).toBe(true);
  });
});


describe('scalar multiplication - random polynomials with prime order', () => {
  const degrees = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
  it.each(cartesian([degrees, __big_primes]))('degrees: %s, order: %s', async (
    degree, order
  ) => {
    const scalar = await randBigint(byteLen(order));
    const poly1 = await Polynomial.random({ degree, order });
    const poly2 = poly1.multScalar(scalar);

    const poly3 = new Polynomial(poly1.coeffs.map((c) => scalar * c), order);
    expect(poly2.isEqual(poly3)).toBe(true);

    const poly4 = new Polynomial([scalar], order);
    expect(poly2.isEqual(poly1.mult(poly4))).toBe(true);
  });
});


describe('evaluation - fixed polynomials small small order', () => {
  it.each(cartesian([
    [
      [],
      [1],
      [1, 2],
      [1, 2, 3],
      [1, 2, 3, 4],
      [1, 2, 3, 4, 5],
      [1, 2, 3, 4, 5, 6],
      [1, 2, 3, 4, 5, 6, 7],
    ],
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    __small_orders,
  ]))('%s %s, %s', async (coeffs, value, order) => {
    const poly = new Polynomial(coeffs, order);
    let acc = 0;
    for (const [i, c] of coeffs.entries()) {
      acc += c * value ** i;
    }
    expect(poly.evaluate(value)).toEqual(BigInt(acc % order));
  });
});


describe('evaluation - random polynomials with prime order', () => {
  const degrees = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
  it.each(cartesian([degrees, __big_primes]))('degrees: %s, order: %s', async (
    degree, order
  ) => {
    const value = await randBigint(byteLen(order));
    const poly = await Polynomial.random({ degree, order });
    let acc = __0n;
    for (const [i, c] of poly.coeffs.entries()) {
      acc += c * value ** BigInt(i);
    }
    expect(poly.evaluate(value)).toEqual(acc % order);
  });
});
