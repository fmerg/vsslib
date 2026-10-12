import { describe } from 'node:test';
import assert from 'node:assert/strict';
import { initBackend } from 'vsslib/backend';
import { mod } from 'vsslib/arith';
import { cartesian, each } from '../utils';
import { resolveTestConfig } from '../environ';

import { computeLambda, computeLambdas, computeLambdaNaive } from 'vsslib/lagrange';

const { systems } = resolveTestConfig();


const wide = (k: number) => Array.from(
  { length: k }, (_, i) => Number.MAX_SAFE_INTEGER - i * 1_000_003 * (i + 1)
);

const indexSets: [string, number[]][] = [
  ['single', [1]],
  ['pair', [1, 2]],
  ['contiguous', [1, 2, 3, 4, 5]],
  ['unordered', [4, 1, 5, 2]],
  ['sparse', [1, 7, 38, 1000, 2 ** 40]],
  // Products of differences outgrow the order and get reduced on the way
  ['wide', wide(25)],
  ['contiguous 100', Array.from({ length: 100 }, (_, i) => i + 1)],
];


describe('Lagrange coefficients - against the naive computation', () => {
  const cases = indexSets.flatMap(([label, indexes]) =>
    systems.map(system => [label, system, indexes] as const)
  );
  each(cases)('%s indexes over %s', async (_, system, indexes) => {
    const ctx = initBackend(system);
    const expected = indexes.map(index => computeLambdaNaive(ctx, index, indexes));
    assert.deepEqual(computeLambdas(ctx, indexes), expected);
    assert.deepEqual(indexes.map(index => computeLambda(ctx, index, indexes)), expected);
  });
});


describe('Lagrange coefficients - interpolation at zero', () => {
  each(cartesian([[1, 3, 9, 25], systems]))('%s indexes over %s', async (k, system) => {
    const ctx = initBackend(system);
    const { order } = ctx;
    const coeffs: bigint[] = [];
    for (let i = 0; i < k; i++) coeffs.push(await ctx.randomScalar());
    const f = (x: number) => coeffs.reduceRight((acc, c) => mod(acc * BigInt(x) + c, order), 0n);
    const indexes = wide(k);
    const lambdas = computeLambdas(ctx, indexes);
    const recovered = indexes.reduce((acc, x, i) => mod(acc + lambdas[i] * f(x), order), 0n);
    assert.equal(recovered, coeffs[0]);
  });
});
