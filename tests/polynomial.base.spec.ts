import { lagrange, backend } from '../src';
import { Systems } from '../src/enums';
import { BasePolynomial } from '../src/lagrange';
import { Messages } from '../src/lagrange/enums';
import { byteLen, randBigint } from '../src/utils';
import { cartesian, trimZeroes } from './helpers';

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
const __small_orders = [2, 3, 4, 5, 6, 7];
const __big_primes = Object.values(Systems).map((label) => backend.initGroup(label).order);


describe('construction - coefficients smaller than order', () => {
  it.each(cartesian([__coeffs_and_degree, __big_primes]))('%s %s', async (
    [coeffs, degree], order
  ) => {
    const poly = new BasePolynomial(coeffs, order);
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
    const poly = new BasePolynomial(coeffs, order);
    expect(poly.coeffs).toEqual(trimZeroes(coeffs).map(BigInt));
    expect(poly.degree).toBe(degree);
    expect(poly.degree).toBe(
      poly.coeffs.length > 0 ? poly.coeffs.length - 1 : -Infinity
    );
  });
});


describe('construction errors', () => {
  test('order not greater than one', async () => {
    expect(() => { new BasePolynomial([], 1) }).toThrow(
      Messages.ORDER_MUST_BE_GT_ONE
    );
  });
});


describe('equal polynomials', () => {
  it.each(cartesian([__coeffs_and_degree, __big_primes]))('%s %s', async (
    [coeffs, degree], order
  ) => {
    const poly1 = new BasePolynomial(coeffs, order);
    const poly2 = new BasePolynomial(coeffs, order);
    const poly3 = new BasePolynomial(
      coeffs.map((num: number) => BigInt(num) + order),
      order
    );
    const poly4 = new BasePolynomial(coeffs.concat([0]), order);
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
    const poly1 = new BasePolynomial(coeffs, order);
    const poly2 = new BasePolynomial(coeffs, order + __1n);
    const poly3 = new BasePolynomial(coeffs.concat([1]), order);
    const poly4 = new BasePolynomial(
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
    const poly = BasePolynomial.zero({ order });
    expect(poly.coeffs).toEqual([]);
    expect(poly.degree).toBe(-Infinity);
    expect(poly.order).toBe(order);
    expect(poly.isZero()).toBe(true);
  });
});


describe('errors', () => {
  test('addition - different orders', async () => {
    const poly1 = new BasePolynomial([], 2);
    const poly2 = new BasePolynomial([], 3);
    expect(() => poly1.add(poly2)).toThrow(
      Messages.DIFFERENT_ORDERS_CANNOT_ADD
    );
  });
  test('multiplication - different orders', async () => {
    const poly1 = new BasePolynomial([], 2);
    const poly2 = new BasePolynomial([], 3);
    expect(() => poly1.mult(poly2)).toThrow(
      Messages.DIFFERENT_ORDERS_CANNOT_MULTIPLY
    );
  });
});


describe('addition - fixed polynomials small order', () => {
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
    const poly1 = new BasePolynomial(coeffs1, order);
    const poly2 = new BasePolynomial(coeffs2.map((num: number) => num + order), order);
    const poly3 = new BasePolynomial(coeffs3, order);
    expect(poly3.isEqual(poly1.add(poly2))).toBe(true);
    expect(poly3.isEqual(poly2.add(poly1))).toBe(true);
  });
});


describe('multiplication - fixed polynomials small order', () => {
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
    const poly1 = new BasePolynomial(coeffs1, order);
    const poly2 = new BasePolynomial(coeffs2.map((num: number) => num + order), order);
    const poly3 = new BasePolynomial(coeffs3, order);
    expect(poly3.isEqual(poly1.mult(poly2))).toBe(true);
    expect(poly3.isEqual(poly2.mult(poly1))).toBe(true);
  });
});


describe('scalar multiplication - fixed polynomials small order', () => {
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
    const poly1 = new BasePolynomial(coeffs, order);
    const poly2 = poly1.multScalar(scalar);

    const poly3 = new BasePolynomial(coeffs.map((c: number) => scalar * c), order);
    expect(poly2.isEqual(poly3)).toBe(true);

    const poly4 = new BasePolynomial([scalar], order);
    expect(poly2.isEqual(poly1.mult(poly4))).toBe(true);
  });
});


describe('evaluation - fixed polynomials small order', () => {
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
    const poly = new BasePolynomial(coeffs, order);
    let acc = 0;
    for (const [i, c] of coeffs.entries()) {
      acc += c * value ** i;
    }
    expect(poly.evaluate(value)).toEqual(BigInt(acc % order));
  });
});
