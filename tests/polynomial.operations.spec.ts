import { Systems } from '../src/enums';
import { Polynomial } from '../src/polynomial';
import { cartesian, trimZeroes } from './helpers';

const polynomial = require('../src/polynomial');
const elgamal = require('../src/elgamal');


const __0n = BigInt(0);
const __1n = BigInt(1);
const __labels = Object.values(Systems);
const __small_orders = [2, 3, 4, 5, 6, 7].map(BigInt);
const __prime_orders = __labels.map((label) => elgamal.initCrypto(label).order);


describe('zero polynomial', () => {
  it.each(__prime_orders)('order: %s', async (order) => {
    const poly = await Polynomial.zero({ order });
    expect(poly.coeffs).toEqual([]);
    expect(poly.degree).toBe(-Infinity);
    expect(poly.order).toBe(order);
    expect(poly.isZero()).toBe(true);
  });
});


describe('addition errors', () => {
  test('different orders', async () => {
    const poly1 = new Polynomial([], BigInt(2));
    const poly2 = new Polynomial([], BigInt(3));
    expect(() => poly1.add(poly2)).toThrow(
      'Could not add polynomials: different orders'
    );
  });
});


describe('addition - predefined polynomials with small order', () => {
  it.each(cartesian([
    [[1, 2, 3, 4], [],                    [1, 2, 3, 4]],
    [[1, 2, 3, 4], [1],                   [2, 2, 3, 4]],
    [[1, 2, 3, 4], [1, 2],                [2, 4, 3, 4]],
    [[1, 2, 3, 4], [1, 2, 3],             [2, 4, 6, 4]],
    [[1, 2, 3, 4], [1, 2, 3, 4],          [2, 4, 6, 8]],
    [[1, 2, 3, 4], [1, 2, 3, 4, 5],       [2, 4, 6, 8, 5]],
    [[1, 2, 3, 4], [1, 2, 3, 4, 5, 6],    [2, 4, 6, 8, 5, 6]],
    [[1, 2, 3, 4], [1, 2, 3, 4, 5, 6, 7], [2, 4, 6, 8, 5, 6, 7]],
  ], __small_orders
  ))('%s %s', async ([coeffs1, coeffs2, coeffs3], order) => {
    const poly1 = new Polynomial(coeffs1.map(BigInt), order);
    const poly2 = new Polynomial(coeffs2.map((num: number) => BigInt(num) + order), order);
    const poly3 = new Polynomial(coeffs3.map(BigInt), order);
    expect(poly3.isEqual(poly1.add(poly2))).toBe(true);
    expect(poly3.isEqual(poly2.add(poly1))).toBe(true);
  });
});


describe('addition - random polynomials with prime order', () => {
  it.each(cartesian([
    [0, 0], [0, 1], [1, 1], [0, 2], [1, 2],
    [2, 2], [5, 7], [6, 9], [7, 9], [8, 9],
  ], __prime_orders))('degrees: %s, order: %s', async (degrees, order) => {
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



describe('multiplication errors', () => {
  test('different orders', async () => {
    const poly1 = new Polynomial([], BigInt(2));
    const poly2 = new Polynomial([], BigInt(3));
    expect(() => poly1.mult(poly2)).toThrow(
      'Could not multiply polynomials: different orders'
    );
  });
});


describe('multiplication - predefined polynomials with small order', () => {
  it.each(cartesian([
    [[1, 2, 3, 4], [],                    []],
    [[1, 2, 3, 4], [1],                   [1, 2, 3, 4]],
    [[1, 2, 3, 4], [1, 2],                [1, 4, 7, 10, 8]],
    [[1, 2, 3, 4], [1, 2, 3],             [1, 4, 10, 16, 17, 12]],
    [[1, 2, 3, 4], [1, 2, 3, 4],          [1, 4, 10, 20, 25, 24, 16]],
    [[1, 2, 3, 4], [1, 2, 3, 4, 5],       [1, 4, 10, 20, 30, 34, 31, 20]],
    [[1, 2, 3, 4], [1, 2, 3, 4, 5, 6],    [1, 4, 10, 20, 30, 40, 43, 38, 24]],
    [[1, 2, 3, 4], [1, 2, 3, 4, 5, 6, 7], [1, 4, 10, 20, 30, 40, 50, 52, 45, 28]],
  ], __small_orders
  ))('%s %s', async ([coeffs1, coeffs2, coeffs3], order) => {
    const poly1 = new Polynomial(coeffs1.map(BigInt), order);
    const poly2 = new Polynomial(coeffs2.map((num: number) => BigInt(num) + order), order);
    const poly3 = new Polynomial(coeffs3.map(BigInt), order);
    expect(poly3.isEqual(poly1.mult(poly2))).toBe(true);
    expect(poly3.isEqual(poly2.mult(poly1))).toBe(true);
  });
});


describe('multiplication - random polynomials with prime order', () => {
  it.each(cartesian([
    [0, 0], [0, 1], [1, 1], [0, 2], [1, 2],
    [2, 2], [5, 7], [6, 9], [7, 9], [8, 9],
  ], __prime_orders))('degrees: %s, order: %s', async ([degree1, degree2], order) => {
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