import { Algorithms } from '../../src/enums';
import { initGroup } from '../../src/backend';
import { cartesian } from '../utils';
import { randomNonce } from '../../src/crypto';
import { createEqDlogPairs } from './helpers';
import { resolveTestConfig } from '../environ';
import nizk from '../../src/nizk';

let { systems, algorithms } = resolveTestConfig();


describe('Success - without nonce', () => {
  it.each(cartesian([systems, algorithms]))('over %s/%s', async (system, algorithm) => {
    const ctx = initGroup(system);
    const [x, pairs] = await createEqDlogPairs(ctx, 3);
    const proof = await nizk(ctx, algorithm).proveEqDlog(x, pairs);
    const valid = await nizk(ctx, algorithm).verifyEqDlog(pairs, proof);
    expect(valid).toBe(true);
  });
});


describe('Success - with nonce', () => {
  it.each(systems)('over %s', async (system) => {
    const ctx = initGroup(system);
    const [x, pairs] = await createEqDlogPairs(ctx, 3);
    const nonce = await randomNonce();
    const proof = await nizk(ctx, Algorithms.SHA256).proveEqDlog(x, pairs, nonce);
    const valid = await nizk(ctx, Algorithms.SHA256).verifyEqDlog(pairs, proof, nonce);
    expect(valid).toBe(true);
  });
});


describe('Failure - forged proof', () => {
  it.each(systems)('over %s', async (system) => {
    const ctx = initGroup(system);
    const [x, pairs] = await createEqDlogPairs(ctx, 3);
    const proof = await nizk(ctx, Algorithms.SHA256).proveEqDlog(x, pairs);
    pairs[2].v = await ctx.randomPoint();
    const valid = await nizk(ctx, Algorithms.SHA256).verifyEqDlog(pairs, proof);
    expect(valid).toBe(false);
  });
});


describe('Failure - missing nonce', () => {
  it.each(systems)('over %s', async (system) => {
    const ctx = initGroup(system);
    const [x, pairs] = await createEqDlogPairs(ctx, 3);
    const nonce = await randomNonce();
    const proof = await nizk(ctx, Algorithms.SHA256).proveEqDlog(x, pairs, nonce);
    const valid = await nizk(ctx, Algorithms.SHA256).verifyEqDlog(pairs, proof);
    expect(valid).toBe(false);
  });
});


describe('Failure - forged nonce', () => {
  it.each(systems)('over %s', async (system) => {
    const ctx = initGroup(system);
    const [x, pairs] = await createEqDlogPairs(ctx, 3);
    const nonce = await randomNonce();
    const proof = await nizk(ctx, Algorithms.SHA256).proveEqDlog(x, pairs, nonce);
    const valid = await nizk(ctx, Algorithms.SHA256).verifyEqDlog(pairs, proof, await randomNonce());
    expect(valid).toBe(false);
  });
});
