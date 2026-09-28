import { initBackend } from 'vsslib/backend';
import { cartesian } from '../utils';
import { interpolate as textbooxInterpolate } from './helpers';
import { resolveTestConfig } from '../environ';

import { lagrange, expandBasis, expandBasisNaive } from 'vsslib/lagrange';

const { systems } = resolveTestConfig();


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
    const poly1 = await lagrange(ctx).interpolate(points);
    const poly2 = textbooxInterpolate(points, order);
    expect(poly2.equals(poly1)).toBe(true);
    for (const [x, y] of points) {
      expect(poly1.evaluate(x)).toEqual(y % order);
      expect(poly1.evaluateBarycentric(x)).toEqual(y % order);
      expect(poly2.evaluate(x)).toEqual(y % order);
    }
    for (const x of [0n, 1n, 7n, await randomScalar()]) {
      const y = poly1.evaluate(x);
      expect(poly1.evaluateNaive(x)).toEqual(y);
      expect(poly1.evaluateBarycentric(x)).toEqual(y);
      expect(poly2.evaluate(x)).toEqual(y);
    }
  });
  it.each(systems)('ok - fixed points - over %s', async (system) => {
    const ctx = initBackend(system);
    for (const points of collectionPairs) {
      const poly1 = await lagrange(ctx).interpolate(points);
      const poly2 = textbooxInterpolate(points, ctx.order);
      expect(poly2.equals(poly1)).toBe(true);
      for (const [x, y] of points) {
        expect(poly1.evaluate(x)).toEqual(BigInt(y) % ctx.order);
        expect(poly1.evaluateBarycentric(x)).toEqual(BigInt(y) % ctx.order);
      }
    }
  });
  it.each(systems)('error - non-distinct x\'s - over %s', async (system) => {
    const ctx = initBackend(system);
    const points: [number, number][] = [[1, 2], [1, 3]];
    await expect(lagrange(ctx).interpolate(points)).rejects.toThrow(
      'Not all provided x\'s are distinct modulo order'
    );
  });
});



describe('Lagrange basis - synthetic division against expansion', () => {
  it.each(cartesian([[0, 1, 2, 3, 5, 9, 25], systems]))(
    'random x\'s - %s points - over %s', async (nrPoints, system) => {
    const ctx = initBackend(system);
    const xs = [];
    for (let i = 0; i < nrPoints; i++) xs.push(await ctx.randomScalar());
    expect(expandBasis(xs, ctx.order)).toEqual(expandBasisNaive(xs, ctx.order));
  });
  it.each(systems)('fixed and repeated x\'s - over %s', async (system) => {
    const order = initBackend(system).order;
    for (const xs of [
      [0n, 1n, 2n, 3n, 4n],
      [5n, -3n, order + 2n, 0n],
      [1n, order + 1n, 7n],
    ]) {
      expect(expandBasis(xs, order)).toEqual(expandBasisNaive(xs, order));
    }
  });
});
