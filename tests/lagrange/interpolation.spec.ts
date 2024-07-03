import { System } from 'vsslib/types';
import { initBackend } from 'vsslib/backend';
import { lagrange } from 'vsslib';
import { cartesian } from '../utils';
import { resolveTestConfig } from '../environ';
import { interpolate } from './helpers';

const { systems } = resolveTestConfig();

const __0n = BigInt(0);
const __1n = BigInt(1);

const collectionPairs: ([number, number][])[] = [
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


describe('Lagrange interpolation', () => {
  it.each(cartesian([[1, 2, 3, 4, 5, 6, 7, 8, 9], systems]))(
    'ok - random points - %s points - over %s', async (nrPoints, system) => {
    const ctx = initBackend(system);
    const { order, randomScalar } = ctx;
    const points = new Array(nrPoints);
    for (let i = 0; i < points.length; i++) {
      const x = await randomScalar();
      const y = await randomScalar();
      points[i] = [x, y];
    }
    const poly1 = await lagrange.interpolate(ctx, points);
    const poly2 = interpolate(points, order);
    expect(poly2.equals(poly1)).toBe(true);
    for (const [x, y] of points) {
      expect(poly1.evaluate(x)).toEqual(y % order);
      expect(poly2.evaluate(x)).toEqual(y % order);
    }
    const x = await randomScalar();
    expect(poly2.evaluate(x)).toEqual(poly1.evaluate(x));
  });
  it.each(systems)('ok - fixed points - over %s', async (system) => {
    const ctx = initBackend(system);
    for (const points of collectionPairs) {
      const poly1 = await lagrange.interpolate(ctx, points);
      const poly2 = interpolate(points, ctx.order);
      expect(poly2.equals(poly1)).toBe(true);
      for (const [x, y] of points) {
        expect(poly1.evaluate(x)).toEqual(BigInt(y) % ctx.order);
      }
    }
  });
  it.each(systems)('error - non-distinct x\'s - over %s', async (system) => {
    const ctx = initBackend(system);
    const points: [number, number][] = [[1, 2], [1, 3]];
    await expect(lagrange.interpolate(ctx, points)).rejects.toThrow(
      'Not all provided x\'s are distinct modulo order'
    );
  });
});

