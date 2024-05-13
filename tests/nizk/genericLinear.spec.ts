import { Algorithms } from '../../src/enums';
import { initGroup } from '../../src/backend';
import { randomBytes } from '../../src/crypto';
import { cartesian } from '../helpers';
import { createGenericLinear } from './helpers';
import { resolveTestConfig } from '../environ';
import nizk from '../../src/nizk';

let { systems, algorithms } = resolveTestConfig();


describe('Success - without nonce', () => {
  it.each(cartesian([systems, algorithms]))('over %s/%s', async (system, algorithm) => {
    const ctx = initGroup(system);
    const [witness, relation] = await createGenericLinear(ctx, { m: 5, n: 3 });
    const proof = await nizk(ctx, algorithm).proveLinear(witness, relation);
    const valid = await nizk(ctx, algorithm).verifyLinear(relation, proof);
    expect(valid).toBe(true);
  });
});


describe('Success - with nonce', () => {
  it.each(systems)('over %s', async (system) => {
    const ctx = initGroup(system);
    const nonce = await randomBytes(16);
    const [witness, relation] = await createGenericLinear(ctx, { m: 5, n: 3 });
    const proof = await nizk(ctx, Algorithms.SHA256).proveLinear(witness, relation, nonce);
    const valid = await nizk(ctx, Algorithms.SHA256).verifyLinear(relation, proof, nonce);
    expect(valid).toBe(true);
  });
});


describe('Failure - forged proof', () => {
  it.each(systems)('over %s', async (system) => {
    const ctx = initGroup(system);
    const [witness, relation] = await createGenericLinear(ctx, { m: 5, n: 3 });
    const proof = await nizk(ctx, Algorithms.SHA256).proveLinear(witness, relation);
    proof.commitment[0] = (await ctx.randomPoint()).toBytes();
    const valid = await nizk(ctx, Algorithms.SHA256).verifyLinear(relation, proof);
    expect(valid).toBe(false);
  });
});


describe('Failure - missing nonce', () => {
  it.each(systems)('over %s', async (system) => {
    const ctx = initGroup(system);
    const [witness, relation] = await createGenericLinear(ctx, { m: 5, n: 3 });
    const nonce = await randomBytes(16);
    const proof = await nizk(ctx, Algorithms.SHA256).proveLinear(witness, relation, nonce);
    const valid = await nizk(ctx, Algorithms.SHA256).verifyLinear(relation, proof);
    expect(valid).toBe(false);
  });
});


describe('Failure - forged nonce', () => {
  it.each(systems)('over %s', async (system) => {
    const ctx = initGroup(system);
    const [witness, relation] = await createGenericLinear(ctx, { m: 5, n: 3 });
    const nonce = await randomBytes(16);
    const proof = await nizk(ctx, Algorithms.SHA256).proveLinear(witness, relation, nonce);
    const valid = await nizk(ctx, Algorithms.SHA256).verifyLinear(relation, proof, await randomBytes(16));
    expect(valid).toBe(false);
  });
});
