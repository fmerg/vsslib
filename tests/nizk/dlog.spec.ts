import { Algorithms } from '../../src/enums';
import { initGroup } from '../../src/backend';
import { cartesian } from '../helpers';
import { createDlogPair } from './helpers';
import { dlog } from '../../src/nizk';
import { resolveTestConfig } from '../environ';

let { systems, algorithms } = resolveTestConfig();



describe('Success - without nonce', () => {
  it.each(cartesian([systems, algorithms]))('over %s/%s', async (system, algorithm) => {
    const ctx = initGroup(system);
    const [x, { u, v }] = await createDlogPair(ctx);
    const proof = await dlog(ctx, algorithm).prove(x, { u, v });
    expect(proof.algorithm).toBe(algorithm || Algorithms.DEFAULT);
    const valid = await dlog(ctx, algorithm).verify({ u, v }, proof);
    expect(valid).toBe(true);
  });
});


describe('Success - with nonce', () => {
  it.each(systems)('over %s', async (system) => {
    const ctx = initGroup(system);
    const [x, { u, v }] = await createDlogPair(ctx);
    const nonce = await ctx.randomBytes();
    const proof = await dlog(ctx, Algorithms.SHA256).prove(x, { u, v }, nonce);
    const valid = await dlog(ctx, Algorithms.SHA256).verify({ u, v }, proof, nonce);
    expect(valid).toBe(true);
  });
});


describe('Failure - forged proof', () => {
  it.each(systems)('over %s', async (system) => {
    const ctx = initGroup(system);
    const [x, { u, v }] = await createDlogPair(ctx);
    const proof = await dlog(ctx, Algorithms.SHA256).prove(x, { u, v });
    proof.response[0] = await ctx.randomScalar();
    const valid = await dlog(ctx, Algorithms.SHA256).verify({ u, v }, proof);
    expect(valid).toBe(false);
  });
});


describe('Failure - wrong algorithm', () => {
  it.each(cartesian([systems, algorithms]))('over %s/%s', async (system, algorithm) => {
    const ctx = initGroup(system);
    const [x, { u, v }] = await createDlogPair(ctx);
    const proof = await dlog(ctx, algorithm).prove(x, { u, v });
    proof.algorithm = (proof.algorithm == Algorithms.SHA256) ?
      Algorithms.SHA512 :
      Algorithms.SHA256;
    const valid = await dlog(ctx, algorithm).verify({ u, v }, proof);
    expect(valid).toBe(false);
  });
});


describe('Failure - missing nonce', () => {
  it.each(systems)('over %s', async (system) => {
    const ctx = initGroup(system);
    const [x, { u, v }] = await createDlogPair(ctx);
    const nonce = await ctx.randomBytes();
    const proof = await dlog(ctx, Algorithms.SHA256).prove(x, { u, v }, nonce);
    const valid = await dlog(ctx, Algorithms.SHA256).verify({ u, v }, proof);
    expect(valid).toBe(false);
  });
});


describe('Failure - forged nonce', () => {
  it.each(systems)('over %s', async (system) => {
    const ctx = initGroup(system);
    const [x, { u, v }] = await createDlogPair(ctx);
    const nonce = await ctx.randomBytes();
    const proof = await dlog(ctx, Algorithms.SHA256).prove(x, { u, v }, nonce);
    const valid = await dlog(ctx, Algorithms.SHA256).verify({ u, v }, proof, await ctx.randomBytes());
    expect(valid).toBe(false);
  });
});
