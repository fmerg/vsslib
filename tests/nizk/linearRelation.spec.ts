import { Algorithms } from '../../src/enums';
import { initGroup } from '../../src/backend';
import { cartesian } from '../helpers';
import { createLinearRelation } from './helpers';
import { resolveTestConfig } from '../environ';
import nizk from '../../src/nizk';

let { systems, algorithms } = resolveTestConfig();


describe('Success - without nonce', () => {
  it.each(cartesian([systems, algorithms]))('over %s/%s', async (system, algorithm) => {
    const ctx = initGroup(system);
    const [witnesses, relation] = await createLinearRelation(ctx, { m: 5, n: 3 });
    const proof = await nizk(ctx, algorithm).proveLinearRelation(witnesses, relation);
    const valid = await nizk(ctx, algorithm).verifyLinearRelation(relation, proof);
    expect(valid).toBe(true);
  });
});


describe('Success - with nonce', () => {
  it.each(systems)('over %s', async (system) => {
    const ctx = initGroup(system);
    const nonce = await ctx.randomBytes();
    const [witnesses, relation] = await createLinearRelation(ctx, { m: 5, n: 3 });
    const proof = await nizk(ctx, Algorithms.SHA256).proveLinearRelation(witnesses, relation, nonce);
    const valid = await nizk(ctx, Algorithms.SHA256).verifyLinearRelation(relation, proof, nonce);
    expect(valid).toBe(true);
  });
});


describe('Failure - forged proof', () => {
  it.each(systems)('over %s', async (system) => {
    const ctx = initGroup(system);
    const [witnesses, relation] = await createLinearRelation(ctx, { m: 5, n: 3 });
    const proof = await nizk(ctx, Algorithms.SHA256).proveLinearRelation(witnesses, relation);
    proof.response[0] = await ctx.randomScalar();
    const valid = await nizk(ctx, Algorithms.SHA256).verifyLinearRelation(relation, proof);
    expect(valid).toBe(false);
  });
});


describe('Failure - missing nonce', () => {
  it.each(systems)('over %s', async (system) => {
    const ctx = initGroup(system);
    const [witnesses, relation] = await createLinearRelation(ctx, { m: 5, n: 3 });
    const nonce = await ctx.randomBytes();
    const proof = await nizk(ctx, Algorithms.SHA256).proveLinearRelation(witnesses, relation, nonce);
    const valid = await nizk(ctx, Algorithms.SHA256).verifyLinearRelation(relation, proof);
    expect(valid).toBe(false);
  });
});


describe('Failure - forged nonce', () => {
  it.each(systems)('over %s', async (system) => {
    const ctx = initGroup(system);
    const [witnesses, relation] = await createLinearRelation(ctx, { m: 5, n: 3 });
    const nonce = await ctx.randomBytes();
    const proof = await nizk(ctx, Algorithms.SHA256).proveLinearRelation(witnesses, relation, nonce);
    const valid = await nizk(ctx, Algorithms.SHA256).verifyLinearRelation(relation, proof, await ctx.randomBytes());
    expect(valid).toBe(false);
  });
});
