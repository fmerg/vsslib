import { describe } from 'node:test';
import assert from 'node:assert/strict';
import { Algorithms } from 'vsslib/enums';
import { initBackend } from 'vsslib/backend';
import { randomNonce } from 'vsslib/random';
import { cartesian, each } from '../utils';
import { createGenericLinear } from './helpers';
import { resolveTestConfig } from '../environ';
import { nizk } from 'vsslib/nizk';

const { systems, algorithms } = resolveTestConfig();


describe('NIZK proof of generik linear relation', () => {
  each(cartesian([systems, algorithms]))(
    'success - without nonce - over %s/%s', async (system, algorithm) => {
    const ctx = initBackend(system);
    const [witness, relation] = await createGenericLinear(ctx, { m: 5, n: 3 });
    const proof = await nizk(ctx, algorithm).proveLinear(witness, relation);
    const isValid = await nizk(ctx, algorithm).verifyLinear(relation, proof);
    assert.equal(isValid, true);
  });
  each(cartesian([systems, algorithms]))(
    'success - with nonce - over %s/%s', async (system, algorithm) => {
    const ctx = initBackend(system);
    const nonce = await randomNonce();
    const [witness, relation] = await createGenericLinear(ctx, { m: 5, n: 3 });
    const proof = await nizk(ctx, algorithm).proveLinear(witness, relation, nonce);
    const isValid = await nizk(ctx, algorithm).verifyLinear(relation, proof, nonce);
    assert.equal(isValid, true);
  });
  each(systems)('failure - forged witness - over %s', async (system) => {
    const ctx = initBackend(system);
    const [_, relation] = await createGenericLinear(ctx, { m: 5, n: 3 });
    const [witness, __] = await createGenericLinear(ctx, { m: 5, n: 3 });
    const proof = await nizk(ctx, Algorithms.SHA256).proveLinear(witness, relation);
    const isValid = await nizk(ctx, Algorithms.SHA256).verifyLinear(relation, proof);
    assert.equal(isValid, false);
  });
  each(systems)('failure - witness of the first row only - over %s', async (system) => {
    // Rows v_i = g ^ x_i with x_0 = x but x_i != x elsewhere: an honest
    // prover with witness x satisfies the first row and fails each other one
    const ctx = initBackend(system);
    const g = ctx.generator;
    const x = await ctx.randomScalar();
    for (const m of [2, 3]) {
      const vs = [await ctx.exp(g, x)];
      for (let i = 1; i < m; i++) vs.push(await ctx.randomPoint());
      const relation = { us: vs.map(() => [g]), vs };
      const proof = await nizk(ctx, Algorithms.SHA256).proveLinear([x], relation);
      const isValid = await nizk(ctx, Algorithms.SHA256).verifyLinear(relation, proof);
      assert.equal(isValid, false, `m = ${m}`);
    }
  });
  each(systems)('failure - forged nonce - over %s', async (system) => {
    const ctx = initBackend(system);
    const [witness, relation] = await createGenericLinear(ctx, { m: 5, n: 3 });
    const nonce = await randomNonce();
    const proof = await nizk(ctx, Algorithms.SHA256).proveLinear(witness, relation, nonce);
    const isValid = await nizk(ctx, Algorithms.SHA256).verifyLinear(relation, proof, await randomNonce());
    assert.equal(isValid, false);
  });
  each(systems)('failure - missing nonce - over %s', async (system) => {
    const ctx = initBackend(system);
    const [witness, relation] = await createGenericLinear(ctx, { m: 5, n: 3 });
    const nonce = await randomNonce();
    const proof = await nizk(ctx, Algorithms.SHA256).proveLinear(witness, relation, nonce);
    const isValid = await nizk(ctx, Algorithms.SHA256).verifyLinear(relation, proof);
    assert.equal(isValid, false);
  });
});
