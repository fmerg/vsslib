import { Algorithms } from '../../src/enums';
import { initBackend } from '../../src/backend';
import { randomNonce } from '../../src/crypto';
import { cartesian } from '../utils';
import { createDDHTuple } from './helpers';
import { resolveTestConfig } from '../environ';

import nizk from '../../src/nizk';

let { systems, algorithms } = resolveTestConfig();



describe('Success - without nonce', () => {
  it.each(cartesian([systems, algorithms]))('over %s/%s', async (system, algorithm) => {
    const ctx = initBackend(system);
    const [z, { u, v, w }] = await createDDHTuple(ctx);
    const proof = await nizk(ctx, algorithm).proveDDH(z, { u, v, w });
    const valid = await nizk(ctx, algorithm).verifyDDH({ u, v, w }, proof);
    expect(valid).toBe(true);
  });
});


describe('Success - with nonce', () => {
  it.each(systems)('over %s', async (system) => {
    const ctx = initBackend(system);
    const [z, { u, v, w }] = await createDDHTuple(ctx);
    const nonce = await randomNonce();
    const proof = await nizk(ctx, Algorithms.SHA256).proveDDH(z, { u, v, w }, nonce);
    const valid = await nizk(ctx, Algorithms.SHA256).verifyDDH({ u, v, w }, proof, nonce);
    expect(valid).toBe(true);
  });
});


describe('Failure - forged proof', () => {
  it.each(systems)('over %s', async (system) => {
    const ctx = initBackend(system);
    const [z, { u, v, w }] = await createDDHTuple(ctx);
    const proof = await nizk(ctx, Algorithms.SHA256).proveDDH(z, { u, v, w })
    proof.commitment[0] = await ctx.randomPublic();
    const valid = await nizk(ctx, Algorithms.SHA256).verifyDDH({ u, v, w }, proof);
    expect(valid).toBe(false);
  });
});


describe('Failure - missing nonce', () => {
  it.each(systems)('over %s', async (system) => {
    const ctx = initBackend(system);
    const [z, { u, v, w }] = await createDDHTuple(ctx);
    const nonce = await randomNonce();
    const proof = await nizk(ctx, Algorithms.SHA256).proveDDH(z, { u, v, w }, nonce);
    const valid = await nizk(ctx, Algorithms.SHA256).verifyDDH({ u, v, w }, proof);
    expect(valid).toBe(false);
  });
});


describe('Failure - forged nonce', () => {
  it.each(systems)('over %s', async (system) => {
    const ctx = initBackend(system);
    const [z, { u, v, w }] = await createDDHTuple(ctx);
    const nonce = await randomNonce();
    const proof = await nizk(ctx, Algorithms.SHA256).proveDDH(z, { u, v, w }, nonce);
    const valid = await nizk(ctx, Algorithms.SHA256).verifyDDH({ u, v, w }, proof, await randomNonce());
    expect(valid).toBe(false);
  });
});
