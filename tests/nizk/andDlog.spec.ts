import { Algorithms } from '../../src/enums';
import { initGroup } from '../../src/backend';
import { cartesian } from '../helpers';
import { createAndDlogPairs } from './helpers';
import { andDlog } from '../../src/nizk';
import { resolveTestConfig } from '../environ';

let { systems, algorithms } = resolveTestConfig();

describe('Success - without nonce', () => {
  it.each(cartesian([systems, algorithms]))('over %s/%s', async (system, algorithm) => {
    const ctx = initGroup(system);
    const [witnesses, pairs] = await createAndDlogPairs(ctx, 5);
    const proof = await andDlog(ctx, algorithm).prove(witnesses, pairs);
    expect(proof.algorithm).toBe(algorithm || Algorithms.DEFAULT);
    const valid = await andDlog(ctx, algorithm).verify(pairs, proof);
    expect(valid).toBe(true);
  });
});


describe('Success - with nonce', () => {
  it.each(systems)('over %s', async (system) => {
    const ctx = initGroup(system);
    const [witnesses, pairs] = await createAndDlogPairs(ctx, 5);
    const nonce = await ctx.randomBytes();
    const proof = await andDlog(ctx, Algorithms.SHA256).prove(witnesses, pairs, nonce);
    const valid = await andDlog(ctx, Algorithms.SHA256).verify(pairs, proof, nonce);
    expect(valid).toBe(true);
  });
});


describe('Failure - forged proof', () => {
  it.each(systems)('over %s', async (system) => {
    const ctx = initGroup(system);
    const [witnesses, pairs] = await createAndDlogPairs(ctx, 5);
    const proof = await andDlog(ctx, Algorithms.SHA256).prove(witnesses, pairs);
    proof.response[0] = await ctx.randomScalar();
    const valid = await andDlog(ctx, Algorithms.SHA256).verify(pairs, proof);
    expect(valid).toBe(false);
  });
});


describe('Failure - wrong algorithm', () => {
  it.each(cartesian([systems, algorithms]))('over %s/%s', async (system, algorithm) => {
    const ctx = initGroup(system);
    const [witnesses, pairs] = await createAndDlogPairs(ctx, 5);
    const proof = await andDlog(ctx, algorithm).prove(witnesses, pairs);
    proof.algorithm = (proof.algorithm == Algorithms.SHA256) ?
      Algorithms.SHA512 :
      Algorithms.SHA256;
    const valid = await andDlog(ctx, algorithm).verify(pairs, proof);
    expect(valid).toBe(false);
  });
});


describe('Failure - missing nonce', () => {
  it.each(systems)('over %s', async (system) => {
    const ctx = initGroup(system);
    const [witnesses, pairs] = await createAndDlogPairs(ctx, 5);
    const nonce = await ctx.randomBytes();
    const proof = await andDlog(ctx, Algorithms.SHA256).prove(witnesses, pairs, nonce);
    const valid = await andDlog(ctx, Algorithms.SHA256).verify(pairs, proof);
    expect(valid).toBe(false);
  });
});


describe('Failure - forged nonce', () => {
  it.each(systems)('over %s', async (system) => {
    const ctx = initGroup(system);
    const nonce = await ctx.randomBytes();
    const [witnesses, pairs] = await createAndDlogPairs(ctx, 5);
    const proof = await andDlog(ctx, Algorithms.SHA256).prove(witnesses, pairs, nonce);
    const valid = await andDlog(ctx, Algorithms.SHA256).verify(pairs, proof, await ctx.randomBytes());
    expect(valid).toBe(false);
  });
});


