import { backend } from '../src'
import { Systems } from '../src/enums';
import { byteLen, randBigint } from '../src/utils';
import { cartesian } from './helpers';
import { Messages } from '../src/polynomials/enums';
import { lagrange } from '../src/polynomials';
const test_helpers = require('./helpers');

const __0n = BigInt(0);
const __1n = BigInt(1);
const __small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29];
const __big_primes = Object.values(Systems).map((label) => backend.initGroup(label).order);
const __labels = Object.values(Systems);


describe('interpolation - errors', () => {
  test('non-distinct x\'s', async () => {
    const points = [[1, 2], [1, 3]];
    expect(() => (lagrange.interpolate(points, { label: 'ed25519' }))).toThrow(
      Messages.INTERPOLATION_NON_DISTINCT_XS +''
    );
  });
});


describe('interpolation - fixed points', () => {
  const collections: ([number, number][])[] = [
    [[0, 1]],
    [[0, 1], [1, 2]],
    [[0, 1], [1, 2], [2, 3]],
    [[0, 1], [1, 2], [2, 3], [3, 4]],
    [[0, 1], [1, 2], [2, 3], [3, 4], [4, 5]],
    [[0, 1], [1, 2], [2, 3], [3, 4], [4, 5], [5, 6]],
    [[0, 1], [1, 2], [2, 3], [3, 4], [4, 5], [5, 6], [6, 7]],
    [[0, 1], [1, 2], [2, 3], [3, 4], [4, 5], [5, 6], [6, 7], [7, 8]],
    [[0, 1], [1, 2], [2, 3], [3, 4], [4, 5], [5, 6], [6, 7], [7, 8], [8, 9]],
  ];
  it.each(__labels)('over %s', async (label) => {
    const order = backend.initGroup(label).order;
    for (const points of collections) {
      const poly1 = test_helpers.interpolate(points, { order });
      const poly2 = lagrange.interpolate(points, { label });
      expect(poly2.isEqual(poly1)).toBe(true);
      for (const [x, y] of points) {
        expect(poly1.evaluate(x)).toEqual(BigInt(y) % order);
        expect(poly2.evaluate(x)).toEqual(BigInt(y) % order);
      }
    }
  });
});


describe('interpolation - random points', () => {
  const numbers = [1, 2, 3, 4, 5, 6, 7, 8, 9];
  it.each(cartesian([numbers, __labels]))('nr points: %s, over: %s', async (nrPoints, label) => {
    const order = backend.initGroup(label).order;
    const points = new Array(nrPoints);
    for (let i = 0; i < points.length; i++) {
      const x = await randBigint(byteLen(order));
      const y = await randBigint(byteLen(order));
      points[i] = [x, y];
    }
    const poly1 = test_helpers.interpolate(points, { order });
    const poly2 = lagrange.interpolate(points, { label });
    expect(poly2.isEqual(poly1)).toBe(true);
    for (const [x, y] of points) {
      expect(poly1.evaluate(x)).toEqual(y % order);
      expect(poly2.evaluate(x)).toEqual(y % order);
    }
    const x = await randBigint(byteLen(order));
    expect(poly2.evaluate(x)).toEqual(poly1.evaluate(x));
  });
});

