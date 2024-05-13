import { Algorithms } from '../../src/enums';
import { initGroup } from '../../src/backend';
import { randomBytes } from '../../src/crypto';
import { cartesian } from '../helpers';
import { createDlogPair } from './helpers';
import { resolveTestConfig } from '../environ';
import nizk from '../../src/nizk';

let { systems, algorithms } = resolveTestConfig();



describe('Success - without nonce', () => {
  it.each(cartesian([systems, algorithms]))('over %s/%s', async (system, algorithm) => {
    const ctx = initGroup(system);
    const [x, { u, v }] = await createDlogPair(ctx);
    const proof = await nizk(ctx, algorithm).proveDlog(x, { u, v });
    const valid = await nizk(ctx, algorithm).verifyDlog({ u, v }, proof);
    expect(valid).toBe(true);
  });
});


describe('Success - with nonce', () => {
  it.each(systems)('over %s', async (system) => {
    const ctx = initGroup(system);
    const [x, { u, v }] = await createDlogPair(ctx);
    const nonce = await randomBytes(16);
    const proof = await nizk(ctx, Algorithms.SHA256).proveDlog(x, { u, v }, nonce);
    const valid = await nizk(ctx, Algorithms.SHA256).verifyDlog({ u, v }, proof, nonce);
    expect(valid).toBe(true);
  });
});


describe('Failure - forged proof', () => {
  it.each(systems)('over %s', async (system) => {
    const ctx = initGroup(system);
    const [x, { u, v }] = await createDlogPair(ctx);
    const proof = await nizk(ctx, Algorithms.SHA256).proveDlog(x, { u, v });
    proof.commitment[0] = (await ctx.randomPoint()).toBytes();
    const valid = await nizk(ctx, Algorithms.SHA256).verifyDlog({ u, v }, proof);
    expect(valid).toBe(false);
  });
});


describe('Failure - missing nonce', () => {
  it.each(systems)('over %s', async (system) => {
    const ctx = initGroup(system);
    const [x, { u, v }] = await createDlogPair(ctx);
    const nonce = await randomBytes(16);
    const proof = await nizk(ctx, Algorithms.SHA256).proveDlog(x, { u, v }, nonce);
    const valid = await nizk(ctx, Algorithms.SHA256).verifyDlog({ u, v }, proof);
    expect(valid).toBe(false);
  });
});


describe('Failure - forged nonce', () => {
  it.each(systems)('over %s', async (system) => {
    const ctx = initGroup(system);
    const [x, { u, v }] = await createDlogPair(ctx);
    const nonce = await randomBytes(16);
    const proof = await nizk(ctx, Algorithms.SHA256).proveDlog(x, { u, v }, nonce);
    const valid = await nizk(ctx, Algorithms.SHA256).verifyDlog({ u, v }, proof, await randomBytes(16));
    expect(valid).toBe(false);
  });
});
