import { Systems } from '../src/enums';
import { byteLen, randomInteger } from '../src/utils';
import { cartesian } from './helpers';
import { Messages } from '../src/lagrange/enums';
const lagrange = require('../src/lagrange');
const elgamal = require('../src/elgamal');
const test_helpers = require('./helpers');


const __0n = BigInt(0);
const __1n = BigInt(1);
const __small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29];
const __big_primes = Object.values(Systems).map((label) => elgamal.initCrypto(label).order);


describe('interpolation - errors', () => {
  test('less than two points', async () => {
    expect(() => (lagrange.interpolate([[1, 2]], { order: 7 }))).toThrow(
      Messages.INTERPOLATION_AT_LEAST_TWO_POINTS_NEEDED
    );
  });
  test('points more than order', async () => {
    const points = [[1, 2],[2, 3],[3, 4]];
    expect(() => (lagrange.interpolate(points, { order: 2 }))).toThrow(
      Messages.INTERPOLATION_NR_POINTS_EXCEEDS_ORDER
    );
  });
  test('non-distinct x\'s', async () => {
    const points = [[1, 2], [1, 3]];
    expect(() => (lagrange.interpolate(points, { order: 7 }))).toThrow(
      Messages.INTERPOLATION_NON_DISTINCT_XS
    );
  });
});


describe('interpolation - fixed points against small prime order', () => {
  const all_collections: ([number, number][])[] = [
    [[0, 1], [1, 2]],
    [[0, 1], [1, 2], [2, 3]],
    [[0, 1], [1, 2], [2, 3], [3, 4]],
    [[0, 1], [1, 2], [2, 3], [3, 4], [4, 5]],
    [[0, 1], [1, 2], [2, 3], [3, 4], [4, 5], [5, 6]],
    [[0, 1], [1, 2], [2, 3], [3, 4], [4, 5], [5, 6], [6, 7]],
    [[0, 1], [1, 2], [2, 3], [3, 4], [4, 5], [5, 6], [6, 7], [7, 8]],
    [[0, 1], [1, 2], [2, 3], [3, 4], [4, 5], [5, 6], [6, 7], [7, 8], [8, 9]],
  ];
  it.each(__small_primes)('%s', async (order) => {
    const collections = all_collections.filter(c => c.length <= order);
    for (const points of collections) {
      const poly1 = test_helpers.interpolate(points, { order });
      const poly2 = lagrange.interpolate(points, { order });
      expect(poly2.isEqual(poly1)).toBe(true);
      for (const [x, y] of points) {
        expect(poly1.evaluate(x)).toEqual(BigInt(y % order));
        expect(poly2.evaluate(x)).toEqual(BigInt(y % order));
      }
      for (let x = 0; x < order; x++) {
        expect(poly2.evaluate(x)).toEqual(poly1.evaluate(x));
      }
    }
  });
});


describe('interpolation - random points against big prime order', () => {
  const numbers = [2, 3, 4, 5, 6, 7, 8, 9];
  it.each(cartesian([numbers, __big_primes]))('nr: %s, order: %s', async (nrPoints, order) => {
    const points = new Array(nrPoints);
    for (let i = 0; i < points.length; i++) {
      const x = await randomInteger(byteLen(order));
      const y = await randomInteger(byteLen(order));
      points[i] = [x, y];
    }
    const poly1 = test_helpers.interpolate(points, { order });
    const poly2 = lagrange.interpolate(points, { order });
    expect(poly2.isEqual(poly1)).toBe(true);
    for (const [x, y] of points) {
      expect(poly1.evaluate(x)).toEqual(y % order);
      expect(poly2.evaluate(x)).toEqual(y % order);
    }
    const x = await randomInteger(byteLen(order));
    expect(poly2.evaluate(x)).toEqual(poly1.evaluate(x));
  });
});

