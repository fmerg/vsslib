import { Systems } from '../src/enums';
import { cartesian } from './helpers';
import { Polynomial } from '../src/polynomial';
import { trimZeroes } from './helpers';

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


describe('construction - all coeffs smaller than order', () => {
  it.each(cartesian(__coeffs_and_degree, __labels))('%s %s', async (
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


describe('construction order - zero coeffs set equal to order', () => {
  it.each(cartesian(__coeffs_and_degree, __labels))('%s %s', async (
    [coeffs, degree], label
  ) => {
    const ctx = elgamal.initCrypto(label);
    const poly = new Polynomial(
      coeffs.map(
        (num: number) => num == 0 ? ctx.order : BigInt(num)
      ),
      ctx.order
    );
    expect(poly.coeffs).toEqual(trimZeroes(coeffs).map(BigInt));
    expect(poly.degree).toBe(degree);
    expect(poly.degree).toBe(
      poly.coeffs.length > 0 ? poly.coeffs.length - 1 : -Infinity
    );
  });
});
