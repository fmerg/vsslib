import { Algorithms } from 'vsslib/enums';
import { initBackend } from 'vsslib/backend';
import { randomNonce } from 'vsslib/random';
import { cartesian } from '../utils';
import { createDDHTuple } from './helpers';
import { resolveTestConfig } from '../environ';

import nizk from 'vsslib/nizk';

let { systems, algorithms } = resolveTestConfig();


describe('NIZK DDH proof (Chaum-Pedersen protocol)', () => {
  it.each(cartesian([systems, algorithms]))(
    'success - without nonce - over %s/%s', async (system, algorithm) => {
    const ctx = initBackend(system);
    const [z, { u, v, w }] = await createDDHTuple(ctx);
    const proof = await nizk(ctx, algorithm).proveDDH(z, { u, v, w });
    const isValid = await nizk(ctx, algorithm).verifyDDH({ u, v, w }, proof);
    expect(isValid).toBe(true);
  });
  it.each(cartesian([systems, algorithms]))(
    'success - with nonce - over %s/%s', async (system, algorithm) => {
    const ctx = initBackend(system);
    const [z, { u, v, w }] = await createDDHTuple(ctx);
    const nonce = await randomNonce();
    const proof = await nizk(ctx, algorithm).proveDDH(z, { u, v, w }, nonce);
    const isValid = await nizk(ctx, algorithm).verifyDDH({ u, v, w }, proof, nonce);
    expect(isValid).toBe(true);
  });
  it.each(systems)('failure - forged secret - over %s', async (system) => {
    const ctx = initBackend(system);
    const [_, { u, v, w }] = await createDDHTuple(ctx);
    const [z, __] = await createDDHTuple(ctx);
    const proof = await nizk(ctx, Algorithms.SHA256).proveDDH(z, { u, v, w })
    const isValid = await nizk(ctx, Algorithms.SHA256).verifyDDH({ u, v, w }, proof);
    expect(isValid).toBe(false);
  });
  it.each(systems)('failure - forged nonce - over %s', async (system) => {
    const ctx = initBackend(system);
    const [z, { u, v, w }] = await createDDHTuple(ctx);
    const nonce = await randomNonce();
    const proof = await nizk(ctx, Algorithms.SHA256).proveDDH(z, { u, v, w }, nonce);
    const isValid = await nizk(ctx, Algorithms.SHA256).verifyDDH({ u, v, w }, proof, await randomNonce());
    expect(isValid).toBe(false);
  });
  it.each(systems)('failure - missing nonce - over %s', async (system) => {
    const ctx = initBackend(system);
    const [z, { u, v, w }] = await createDDHTuple(ctx);
    const nonce = await randomNonce();
    const proof = await nizk(ctx, Algorithms.SHA256).proveDDH(z, { u, v, w }, nonce);
    const isValid = await nizk(ctx, Algorithms.SHA256).verifyDDH({ u, v, w }, proof);
    expect(isValid).toBe(false);
  });
});
