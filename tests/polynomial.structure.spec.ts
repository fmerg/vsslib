import { Systems } from '../src/enums';
import { Polynomial } from '../src/polynomial';
import { cartesian, trimZeroes } from './helpers';

const polynomial = require('../src/polynomial');
const elgamal = require('../src/elgamal');


const __labels = Object.values(Systems);
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
const __1n = BigInt(1);


describe('construction - coeffs smaller than order', () => {
  it.each(cartesian([__coeffs_and_degree, __labels]))('%s %s', async (
    [coeffs, degree], label
  ) => {
    const ctx = elgamal.initCrypto(label);
    const poly = new Polynomial(coeffs.map(BigInt), ctx.order);
    expect(poly.coeffs).toEqual(trimZeroes(coeffs).map(BigInt));
    expect(poly.degree).toBe(degree);
    expect(poly.degree).toBe(
      poly.coeffs.length > 0 ? poly.coeffs.length - 1 : -Infinity
    );
  });
});


describe('construction - coeffs greater than order', () => {
  it.each(cartesian([__coeffs_and_degree, __labels]))('%s %s', async (
    [coeffs, degree], label
  ) => {
    const ctx = elgamal.initCrypto(label);
    const poly = new Polynomial(
      coeffs.map((num: number) => BigInt(num) + ctx.order),
      ctx.order
    );
    expect(poly.coeffs).toEqual(trimZeroes(coeffs).map(BigInt));
    expect(poly.degree).toBe(degree);
    expect(poly.degree).toBe(
      poly.coeffs.length > 0 ? poly.coeffs.length - 1 : -Infinity
    );
  });
});


describe('construction errors', () => {
  test('order not greater than one', async () => {
    expect(() => { new Polynomial([], BigInt(1)) }).toThrow(
      'Polynomial order must be > 1'
    );
  });
});


describe('equal', () => {
  it.each(cartesian([__coeffs_and_degree, __labels]))('%s %s', async (
    [coeffs, degree], label
  ) => {
    const ctx = elgamal.initCrypto(label);
    const poly1 = new Polynomial(coeffs.map(BigInt), ctx.order);
    const poly2 = new Polynomial(coeffs.map(BigInt), ctx.order);
    const poly3 = new Polynomial(
      coeffs.map((num: number) => BigInt(num) + ctx.order),
      ctx.order
    );
    const poly4 = new Polynomial(coeffs.concat([0]).map(BigInt), ctx.order);
    const poly5 = poly1.clone();

    expect(poly1.isEqual(poly1)).toBe(true);
    expect(poly2.isEqual(poly1)).toBe(true);
    expect(poly3.isEqual(poly1)).toBe(true);
    expect(poly4.isEqual(poly1)).toBe(true);
    expect(poly5.isEqual(poly1)).toBe(true);
  });
});


describe('non-equal', () => {
  it.each(cartesian([__coeffs_and_degree, __labels]))('%s %s', async (
    [coeffs, degree], label
  ) => {
    const ctx = elgamal.initCrypto(label);
    const poly1 = new Polynomial(coeffs.map(BigInt), ctx.order);
    const poly2 = new Polynomial(coeffs.map(BigInt), ctx.order + __1n);
    const poly3 = new Polynomial(coeffs.concat([1]).map(BigInt), ctx.order);
    const poly4 = new Polynomial(
      ([666].concat([...coeffs.slice(coeffs.length - 1)])).map(BigInt),
      ctx.order
    );
    const poly5 = poly4.clone();
    expect(poly3.isEqual(poly1)).toBe(false);
    expect(poly2.isEqual(poly1)).toBe(false);
    expect(poly4.isEqual(poly1)).toBe(false);
    expect(poly5.isEqual(poly1)).toBe(false);
  });
});


describe('random polynomial error', () => {
  test('non-positive degree', async () => {
    await expect(Polynomial.random({ degree: -1, order: BigInt(2) })).rejects.toThrow(
      'Polynomial degree must be >= 0'
    );
  });
});


describe('random polynomial', () => {
  it.each(cartesian([[0, 1, 2, 3, 4, 5, 6, 7, 8], __labels]))('degre %s over %s', async (
    degree, label
  ) => {
    const order = elgamal.initCrypto(label).order;
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
