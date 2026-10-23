import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { Systems } from 'vsslib/enums';
import { initBackend } from 'vsslib/backend';
import { BasePolynomial } from 'vsslib/polynomials/base';
import { cartesian, trimZeroes, each } from '../utils';

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
const __big_primes = Object.values(Systems).map((system) => initBackend(system).order);


describe('Construction - coefficients smaller than order', () => {
  each(cartesian([__coeffs_and_degree, __big_primes]))('%s %s', async (
    [coeffs, degree], order
  ) => {
    const poly = new BasePolynomial(coeffs, order);
    assert.deepEqual(poly.coeffs, trimZeroes(coeffs).map(BigInt));
    assert.equal(poly.degree, degree);
    assert.equal(poly.degree, poly.coeffs.length > 0 ? poly.coeffs.length - 1 : -Infinity);
  });
});


describe('Construction - coefficients greater than order', () => {
  each(cartesian([__coeffs_and_degree, __big_primes]))('%s %s', async (
    [coeffs, degree], order
  ) => {
    // Each coefficient shifted by the order, which construction reduces away
    const poly = new BasePolynomial(coeffs.map((num: number) => BigInt(num) + order), order);
    assert.deepEqual(poly.coeffs, trimZeroes(coeffs).map(BigInt));
    assert.equal(poly.degree, degree);
    assert.equal(poly.degree, poly.coeffs.length > 0 ? poly.coeffs.length - 1 : -Infinity);
  });
});


describe('Construction errors', () => {
  test('Order not greater than one', async () => {
    assert.throws(() => { new BasePolynomial([], 1) }, /Order must be > 1/);
  });
});


describe('Equal polynomials', () => {
  each(cartesian([__coeffs_and_degree, __big_primes]))('%s %s', async (
    [coeffs], order
  ) => {
    const poly1 = new BasePolynomial(coeffs, order);
    const poly2 = new BasePolynomial(coeffs, order);
    const poly3 = new BasePolynomial(
      coeffs.map((num: number) => BigInt(num) + order),
      order
    );
    const poly4 = new BasePolynomial(coeffs.concat([0]), order);
    const poly5 = poly1.clone();

    assert.equal(poly1.equals(poly1), true);
    assert.equal(poly2.equals(poly1), true);
    assert.equal(poly3.equals(poly1), true);
    assert.equal(poly4.equals(poly1), true);
    assert.equal(poly5.equals(poly1), true);
  });
});


describe('Non-equal polynomials', () => {
  each(cartesian([__coeffs_and_degree, __big_primes]))('%s %s', async (
    [coeffs], order
  ) => {
    const poly1 = new BasePolynomial(coeffs, order);
    const poly2 = new BasePolynomial(coeffs, order + __1n);
    const poly3 = new BasePolynomial(coeffs.concat([1]), order);
    const poly4 = new BasePolynomial(
      ([666].concat([...coeffs.slice(coeffs.length - 1)])),
      order
    );
    const poly5 = poly4.clone();
    assert.equal(poly3.equals(poly1), false);
    assert.equal(poly2.equals(poly1), false);
    assert.equal(poly4.equals(poly1), false);
    assert.equal(poly5.equals(poly1), false);
  });
});


describe('Zero polynomial', () => {
  each(__big_primes)('order: %s', async (order) => {
    const poly = BasePolynomial.zero({ order });
    assert.deepEqual(poly.coeffs, []);
    assert.equal(poly.degree, -Infinity);
    assert.equal(poly.order, order);
    assert.equal(poly.isZero(), true);
  });
});


describe('Algebraic operations errors', () => {
  test('Addition error - different orders', async () => {
    const poly1 = new BasePolynomial([], 2);
    const poly2 = new BasePolynomial([], 3);
    assert.throws(() => poly1.add(poly2), /Cannot add polynomials with different order/);
  });
  test('Multiplication error - different orders', async () => {
    const poly1 = new BasePolynomial([], 2);
    const poly2 = new BasePolynomial([], 3);
    assert.throws(() => poly1.mult(poly2), /Cannot multiply polynomials with different order/);
  });
});


describe('Addition', () => {
  each(cartesian([
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
    assert.equal(poly3.equals(poly1.add(poly2)), true);
    assert.equal(poly3.equals(poly2.add(poly1)), true);
  });
});


describe('Multiplication', () => {
  each(cartesian([
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
    assert.equal(poly3.equals(poly1.mult(poly2)), true);
    assert.equal(poly3.equals(poly2.mult(poly1)), true);
  });
});


describe('Scalar multiplication', () => {
  each(cartesian([
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
    assert.equal(poly2.equals(poly3), true);

    const poly4 = new BasePolynomial([scalar], order);
    assert.equal(poly2.equals(poly1.mult(poly4)), true);
  });
});


describe('Evaluation', () => {
  each(cartesian([
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
    assert.equal(poly.evaluate(value), BigInt(acc % order));
    assert.equal(poly.evaluateNaive(value), BigInt(acc % order));
  });
});


describe('Evaluation - Horner against power sum', () => {
  each(Object.values(Systems))('%s', async (system) => {
    const ctx = initBackend(system);
    const order = ctx.order;
    // Small x reduces rarely, x above the square root of the order at about
    // every step; 2^32 and 2^53 were earlier bounds
    const root = 1n << BigInt(order.toString(2).length >> 1);
    const values = [
      0n, 1n, 2n, 7n, 50n, 0xffffffffn, 0x100000000n, 2n ** 53n - 1n, 2n ** 53n + 1n,
      root - 1n, root, root + 1n, order - 1n, order, order + 7n, -1n, -order - 3n,
    ];
    for (const degree of [0, 1, 2, 4, 24, 25, 32, 300]) {
      const coeffs = [];
      for (let i = 0; i < degree + 1; i++) coeffs.push(await ctx.randomScalar());
      const poly = new BasePolynomial(coeffs, order);
      for (const value of [...values, await ctx.randomScalar()]) {
        assert.equal(poly.evaluate(value), poly.evaluateNaive(value));
      }
    }
  });
});


describe('Evaluation - orders beyond Number range', () => {
  // Custom backends may have orders far above 2^1024, where conversions to
  // Number overflow
  each([1031n, 2203n, 4253n])('2^%s - 1', async (exponent) => {
    const order = 2n ** exponent - 1n;
    const values = [0n, 7n, 0xffffffffn, 2n ** 1100n + 3n, order - 1n];
    for (const degree of [0, 1, 40]) {
      const coeffs = [];
      for (let i = 0; i < degree + 1; i++) coeffs.push(order - 1n - BigInt(i));
      const poly = new BasePolynomial(coeffs, order);
      for (const value of values) {
        assert.equal(poly.evaluate(value), poly.evaluateNaive(value));
      }
    }
  });
});
