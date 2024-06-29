import { Algorithms } from '../../src/enums';
import { initBackend } from '../../src/backend';
import { randomNonce } from '../../src/crypto';
import { cartesian } from '../utils';
import { createDlogPair } from './helpers';
import { resolveTestConfig } from '../environ';
import nizk from '../../src/nizk';

let { systems, algorithms } = resolveTestConfig();


describe('NIZK Dlog proof (Schnorr protocol)', () => {
  it.each(cartesian([systems, algorithms]))(
    'success - without nonce - over %s/%s', async (system, algorithm) => {
    const ctx = initBackend(system);
    const [x, { u, v }] = await createDlogPair(ctx);
    const proof = await nizk(ctx, algorithm).proveDlog(x, { u, v });
    const valid = await nizk(ctx, algorithm).verifyDlog({ u, v }, proof);
    expect(valid).toBe(true);
  });
  it.each(cartesian([systems, algorithms]))(
    'success - with nonce - over %s/%s', async (system, algorithm) => {
    const ctx = initBackend(system);
    const [x, { u, v }] = await createDlogPair(ctx);
    const nonce = await randomNonce();
    const proof = await nizk(ctx, algorithm).proveDlog(x, { u, v }, nonce);
    const valid = await nizk(ctx, algorithm).verifyDlog({ u, v }, proof, nonce);
    expect(valid).toBe(true);
  });
  it.each(systems)('failure - forged secret - over %s', async (system) => {
    const ctx = initBackend(system);
    const [_, { u, v }] = await createDlogPair(ctx);
    const [x, __] = await createDlogPair(ctx);
    const proof = await nizk(ctx, Algorithms.SHA256).proveDlog(x, { u, v });
    const valid = await nizk(ctx, Algorithms.SHA256).verifyDlog({ u, v }, proof);
    expect(valid).toBe(false);
  });
  it.each(systems)('failure - forged nonce - over %s', async (system) => {
    const ctx = initBackend(system);
    const [x, { u, v }] = await createDlogPair(ctx);
    const nonce = await randomNonce();
    const proof = await nizk(ctx, Algorithms.SHA256).proveDlog(x, { u, v }, nonce);
    const valid = await nizk(ctx, Algorithms.SHA256).verifyDlog({ u, v }, proof, await randomNonce());
    expect(valid).toBe(false);
  });
  it.each(systems)('failure - missing nonce - over %s', async (system) => {
    const ctx = initBackend(system);
    const [x, { u, v }] = await createDlogPair(ctx);
    const nonce = await randomNonce();
    const proof = await nizk(ctx, Algorithms.SHA256).proveDlog(x, { u, v }, nonce);
    const valid = await nizk(ctx, Algorithms.SHA256).verifyDlog({ u, v }, proof);
    expect(valid).toBe(false);
  });
});
