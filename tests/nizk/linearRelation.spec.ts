import { Algorithms } from '../../src/enums';
import { initGroup } from '../../src/backend';
import { cartesian } from '../helpers';
import { createLinearRelation } from './helpers';
import { linearRelation } from '../../src/nizk';
import { resolveTestConfig } from '../environ';

let { systems, algorithms } = resolveTestConfig();


describe('Success - without nonce', () => {
  it.each(cartesian([systems, algorithms]))('over %s/%s', async (system, algorithm) => {
    const ctx = initGroup(system);
    const [witnesses, relation] = await createLinearRelation(ctx, { m: 5, n: 3 });
    const proof = await linearRelation(ctx, algorithm).prove(witnesses, relation);
    expect(proof.algorithm).toBe(algorithm || Algorithms.DEFAULT);
    const valid = await linearRelation(ctx, algorithm).verify(relation, proof);
    expect(valid).toBe(true);
  });
});


describe('Success - with nonce', () => {
  it.each(systems)('over %s', async (system) => {
    const ctx = initGroup(system);
    const nonce = await ctx.randomBytes();
    const [witnesses, relation] = await createLinearRelation(ctx, { m: 5, n: 3 });
    const proof = await linearRelation(ctx, Algorithms.SHA256).prove(witnesses, relation, nonce);
    const valid = await linearRelation(ctx, Algorithms.SHA256).verify(relation, proof, nonce);
    expect(valid).toBe(true);
  });
});


describe('Failure - forged proof', () => {
  it.each(systems)('over %s', async (system) => {
    const ctx = initGroup(system);
    const [witnesses, relation] = await createLinearRelation(ctx, { m: 5, n: 3 });
    const proof = await linearRelation(ctx, Algorithms.SHA256).prove(witnesses, relation);
    proof.response[0] = await ctx.randomScalar();
    const valid = await linearRelation(ctx, Algorithms.SHA256).verify(relation, proof);
    expect(valid).toBe(false);
  });
});


describe('Failure - wrong algorithm', () => {
  it.each(cartesian([systems, algorithms]))('over %s/%s', async (system, algorithm) => {
    const ctx = initGroup(system);
    const [witnesses, relation] = await createLinearRelation(ctx, { m: 5, n: 3 });
    const proof = await linearRelation(ctx, algorithm).prove(witnesses, relation);
    proof.algorithm = (proof.algorithm == Algorithms.SHA256) ?
      Algorithms.SHA512 :
      Algorithms.SHA256;
    const valid = await linearRelation(ctx, algorithm).verify(relation, proof);
    expect(valid).toBe(false);
  });
});


describe('Failure - missing nonce', () => {
  it.each(systems)('over %s', async (system) => {
    const ctx = initGroup(system);
    const [witnesses, relation] = await createLinearRelation(ctx, { m: 5, n: 3 });
    const nonce = await ctx.randomBytes();
    const proof = await linearRelation(ctx, Algorithms.SHA256).prove(witnesses, relation, nonce);
    const valid = await linearRelation(ctx, Algorithms.SHA256).verify(relation, proof);
    expect(valid).toBe(false);
  });
});


describe('Failure - forged nonce', () => {
  it.each(systems)('over %s', async (system) => {
    const ctx = initGroup(system);
    const [witnesses, relation] = await createLinearRelation(ctx, { m: 5, n: 3 });
    const nonce = await ctx.randomBytes();
    const proof = await linearRelation(ctx, Algorithms.SHA256).prove(witnesses, relation, nonce);
    const valid = await linearRelation(ctx, Algorithms.SHA256).verify(relation, proof, await ctx.randomBytes());
    expect(valid).toBe(false);
  });
});
