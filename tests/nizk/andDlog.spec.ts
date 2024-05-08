import { Algorithms } from '../../src/enums';
import { initGroup } from '../../src/backend';
import { cartesian } from '../helpers';
import { createAndDlogPairs } from './helpers';
import { resolveTestConfig } from '../environ';
import nizk from '../../src/nizk';

let { systems, algorithms } = resolveTestConfig();

describe('Success - without nonce', () => {
  it.each(cartesian([systems, algorithms]))('over %s/%s', async (system, algorithm) => {
    const ctx = initGroup(system);
    const [witness, pairs] = await createAndDlogPairs(ctx, 5);
    const proof = await nizk(ctx, algorithm).proveAndDlog(witness, pairs);
    const valid = await nizk(ctx, algorithm).verifyAndDlog(pairs, proof);
    expect(valid).toBe(true);
  });
});


describe('Success - with nonce', () => {
  it.each(systems)('over %s', async (system) => {
    const ctx = initGroup(system);
    const [witness, pairs] = await createAndDlogPairs(ctx, 5);
    const nonce = await ctx.randomBytes();
    const proof = await nizk(ctx, Algorithms.SHA256).proveAndDlog(witness, pairs, nonce);
    const valid = await nizk(ctx, Algorithms.SHA256).verifyAndDlog(pairs, proof, nonce);
    expect(valid).toBe(true);
  });
});


describe('Failure - forged proof', () => {
  it.each(systems)('over %s', async (system) => {
    const ctx = initGroup(system);
    const [witness, pairs] = await createAndDlogPairs(ctx, 5);
    const proof = await nizk(ctx, Algorithms.SHA256).proveAndDlog(witness, pairs);
    proof.commitment[0] = (await ctx.randomPoint()).toBytes();
    const valid = await nizk(ctx, Algorithms.SHA256).verifyAndDlog(pairs, proof);
    expect(valid).toBe(false);
  });
});


describe('Failure - missing nonce', () => {
  it.each(systems)('over %s', async (system) => {
    const ctx = initGroup(system);
    const [witness, pairs] = await createAndDlogPairs(ctx, 5);
    const nonce = await ctx.randomBytes();
    const proof = await nizk(ctx, Algorithms.SHA256).proveAndDlog(witness, pairs, nonce);
    const valid = await nizk(ctx, Algorithms.SHA256).verifyAndDlog(pairs, proof);
    expect(valid).toBe(false);
  });
});


describe('Failure - forged nonce', () => {
  it.each(systems)('over %s', async (system) => {
    const ctx = initGroup(system);
    const nonce = await ctx.randomBytes();
    const [witness, pairs] = await createAndDlogPairs(ctx, 5);
    const proof = await nizk(ctx, Algorithms.SHA256).proveAndDlog(witness, pairs, nonce);
    const valid = await nizk(ctx, Algorithms.SHA256).verifyAndDlog(pairs, proof, await ctx.randomBytes());
    expect(valid).toBe(false);
  });
});


