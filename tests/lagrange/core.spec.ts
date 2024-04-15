import { backend } from '../../src'
import { Systems } from '../../src/enums';
import { Messages } from '../../src/lagrange/enums';
import { cartesian } from '../helpers';
import { interpolate } from './helpers';
// const lagrange = require('../../src/lagrange');
import { lagrange } from '../../src';

const __0n = BigInt(0);
const __1n = BigInt(1);
const __labels = Object.values(Systems);


describe('Interpolation - errors', () => {
  test('Non-distinct x\'s', async () => {
    const ctx = backend.initGroup('ed25519')
    const points: [number, number][] = [[1, 2], [1, 3]];
    await expect(lagrange.interpolate(ctx, points)).rejects.toThrow(
      Messages.INTERPOLATION_NON_DISTINCT_XS
    );
  });
});


describe('Interpolation - fixed points', () => {
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
    const ctx = backend.initGroup(label);
    const { order } = ctx;
    for (const points of collections) {
      const poly1 = await lagrange.interpolate(ctx, points);
      const poly2 = interpolate(points, { order });
      expect(poly2.equals(poly1)).toBe(true);
      for (const [x, y] of points) {
        expect(poly1.evaluate(x)).toEqual(BigInt(y) % order);
      }
    }
  });
});


describe('Interpolation - random points', () => {
  const numbers = [1, 2, 3, 4, 5, 6, 7, 8, 9];
  it.each(cartesian([numbers, __labels]))('%s points over %s', async (nrPoints, label) => {
    const ctx = backend.initGroup(label);
    const { order, randomScalar } = ctx;
    const points = new Array(nrPoints);
    for (let i = 0; i < points.length; i++) {
      const x = await randomScalar();
      const y = await randomScalar();
      points[i] = [x, y];
    }
    const poly1 = await lagrange.interpolate(ctx, points);
    const poly2 = interpolate(points, { order });
    expect(poly2.equals(poly1)).toBe(true);
    for (const [x, y] of points) {
      expect(poly1.evaluate(x)).toEqual(y % order);
      expect(poly2.evaluate(x)).toEqual(y % order);
    }
    const x = await randomScalar();
    expect(poly2.evaluate(x)).toEqual(poly1.evaluate(x));
  });
});

