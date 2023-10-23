import { Systems } from '../src/enums';
import { Polynomial } from '../src/lagrange';
import { Messages } from '../src/lagrange/enums';
import { cartesian, trimZeroes } from './helpers';

const lagrange = require('../src/lagrange');
const elgamal = require('../src/elgamal');

const __0n = BigInt(0);
const __1n = BigInt(1);
const __coeffs_and_degree = [
  [[], -Infinity],
  [[0], -Infinity],
  [[1], 0],
  [[0, 0], -Infinity],
  [[1, 0], 0],
  [[0, 1], 1],
  [[1, 1], 1],
  [[0, 0, 0], -Infinity],
  [[1, 0, 0], 0],
  [[0, 1, 0], 1],
  [[0, 0, 1], 2],
  [[1, 1, 0], 1],
  [[1, 0, 1], 2],
  [[0, 1, 1], 2],
  [[1, 1, 1], 2],
];
const __big_primes = Object.values(Systems).map((label) => elgamal.initCrypto(label).order);


describe('construction - coefficients smaller than order', () => {
  it.each(cartesian([__coeffs_and_degree, __big_primes]))('%s %s', async (
    [coeffs, degree], order
  ) => {
    const poly = new Polynomial(coeffs, order);
    expect(poly.coeffs).toEqual(trimZeroes(coeffs).map(BigInt));
    expect(poly.degree).toBe(degree);
    expect(poly.degree).toBe(
      poly.coeffs.length > 0 ? poly.coeffs.length - 1 : -Infinity
    );
  });
});


describe('construction - coefficients greater than order', () => {
  it.each(cartesian([__coeffs_and_degree, __big_primes]))('%s %s', async (
    [coeffs, degree], order
  ) => {
    const poly = new Polynomial(coeffs, order);
    expect(poly.coeffs).toEqual(trimZeroes(coeffs).map(BigInt));
    expect(poly.degree).toBe(degree);
    expect(poly.degree).toBe(
      poly.coeffs.length > 0 ? poly.coeffs.length - 1 : -Infinity
    );
  });
});


describe('construction errors', () => {
  test('order not greater than one', async () => {
    expect(() => { new Polynomial([], 1) }).toThrow(
      Messages.ORDER_MUST_BE_GT_ONE
    );
  });
});


describe('equal polynomials', () => {
  it.each(cartesian([__coeffs_and_degree, __big_primes]))('%s %s', async (
    [coeffs, degree], order
  ) => {
    const poly1 = new Polynomial(coeffs, order);
    const poly2 = new Polynomial(coeffs, order);
    const poly3 = new Polynomial(
      coeffs.map((num: number) => BigInt(num) + order),
      order
    );
    const poly4 = new Polynomial(coeffs.concat([0]), order);
    const poly5 = poly1.clone();

    expect(poly1.isEqual(poly1)).toBe(true);
    expect(poly2.isEqual(poly1)).toBe(true);
    expect(poly3.isEqual(poly1)).toBe(true);
    expect(poly4.isEqual(poly1)).toBe(true);
    expect(poly5.isEqual(poly1)).toBe(true);
  });
});


describe('non-equal polynomials', () => {
  it.each(cartesian([__coeffs_and_degree, __big_primes]))('%s %s', async (
    [coeffs, degree], order
  ) => {
    const poly1 = new Polynomial(coeffs, order);
    const poly2 = new Polynomial(coeffs, order + __1n);
    const poly3 = new Polynomial(coeffs.concat([1]), order);
    const poly4 = new Polynomial(
      ([666].concat([...coeffs.slice(coeffs.length - 1)])),
      order
    );
    const poly5 = poly4.clone();
    expect(poly3.isEqual(poly1)).toBe(false);
    expect(poly2.isEqual(poly1)).toBe(false);
    expect(poly4.isEqual(poly1)).toBe(false);
    expect(poly5.isEqual(poly1)).toBe(false);
  });
});


describe('zero polynomial', () => {
  it.each(__big_primes)('order: %s', async (order) => {
    const poly = Polynomial.zero({ order });
    expect(poly.coeffs).toEqual([]);
    expect(poly.degree).toBe(-Infinity);
    expect(poly.order).toBe(order);
    expect(poly.isZero()).toBe(true);
  });
});


describe('random polynomial error', () => {
  test('non-positive degree', async () => {
    await expect(Polynomial.random({ degree: -1, order: 2 })).rejects.toThrow(
      Messages.DEGREE_MUST_BE_GE_ZERO
    );
  });
});


describe('random polynomial', () => {
  it.each(cartesian([[0, 1, 2, 3, 4, 5, 6, 7, 8], __big_primes]))('degree %s over %s', async (
    degree, order
  ) => {
    const poly = await Polynomial.random({ degree, order });
    expect(poly.isZero()).toBe(false);
    expect(poly.degree).toEqual(degree);
    expect(poly.order).toEqual(order);
    let flag = true;
    for (const coeff of poly.coeffs) {
      flag &&= (coeff < order);
    }
    expect(flag).toBe(true);
  });
})
