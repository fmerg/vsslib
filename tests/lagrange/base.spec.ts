import { Systems } from '../../src/enums';
import { lagrange, backend } from '../../src';
import { BasePolynomial } from '../../src/lagrange/base';
import { ErrorMessages } from '../../src/errors';
import { cartesian, trimZeroes } from '../helpers';

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


describe('Construction - coefficients smaller than order', () => {
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


describe('Construction - coefficients greater than order', () => {
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


describe('Construction errors', () => {
  test('Order not greater than one', async () => {
    expect(() => { new BasePolynomial([], 1) }).toThrow(
      ErrorMessages.ORDER_NOT_ABOVE_ONE
    );
  });
});


describe('Equal polynomials', () => {
  it.each(cartesian([__coeffs_and_degree, __big_primes]))('', async (
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

    expect(poly1.equals(poly1)).toBe(true);
    expect(poly2.equals(poly1)).toBe(true);
    expect(poly3.equals(poly1)).toBe(true);
    expect(poly4.equals(poly1)).toBe(true);
    expect(poly5.equals(poly1)).toBe(true);
  });
});


describe('Non-equal polynomials', () => {
  it.each(cartesian([__coeffs_and_degree, __big_primes]))('', async (
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
    expect(poly3.equals(poly1)).toBe(false);
    expect(poly2.equals(poly1)).toBe(false);
    expect(poly4.equals(poly1)).toBe(false);
    expect(poly5.equals(poly1)).toBe(false);
  });
});


describe('Zero polynomial', () => {
  it.each(__big_primes)('order: %s', async (order) => {
    const poly = BasePolynomial.zero({ order });
    expect(poly.coeffs).toEqual([]);
    expect(poly.degree).toBe(-Infinity);
    expect(poly.order).toBe(order);
    expect(poly.isZero()).toBe(true);
  });
});


describe('Algebraic operations errors', () => {
  test('Addition error - different orders', async () => {
    const poly1 = new BasePolynomial([], 2);
    const poly2 = new BasePolynomial([], 3);
    expect(() => poly1.add(poly2)).toThrow(
      ErrorMessages.DIFFERENT_ORDERS_CANNOT_ADD
    );
  });
  test('Multiplication error - different orders', async () => {
    const poly1 = new BasePolynomial([], 2);
    const poly2 = new BasePolynomial([], 3);
    expect(() => poly1.mult(poly2)).toThrow(
      ErrorMessages.DIFFERENT_ORDERS_CANNOT_MULTIPLY
    );
  });
});


describe('Addition', () => {
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
    expect(poly3.equals(poly1.add(poly2))).toBe(true);
    expect(poly3.equals(poly2.add(poly1))).toBe(true);
  });
});


describe('Multiplication', () => {
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
    expect(poly3.equals(poly1.mult(poly2))).toBe(true);
    expect(poly3.equals(poly2.mult(poly1))).toBe(true);
  });
});


describe('Scalar multiplication', () => {
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
    expect(poly2.equals(poly3)).toBe(true);

    const poly4 = new BasePolynomial([scalar], order);
    expect(poly2.equals(poly1.mult(poly4))).toBe(true);
  });
});


describe('Evaluation', () => {
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
