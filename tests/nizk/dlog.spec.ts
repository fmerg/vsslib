import { describe } from 'node:test';
import assert from 'node:assert/strict';
import { each } from '../utils';
import { Algorithms } from 'vsslib/enums';
import { initBackend } from 'vsslib/backend';
import { randomNonce } from 'vsslib/random';
import { cartesian } from '../utils';
import { createDlogPair } from './helpers';
import { resolveTestConfig } from '../environ';
import { nizk } from 'vsslib/nizk';

const { systems, algorithms } = resolveTestConfig();


describe('NIZK Dlog proof (Schnorr protocol)', () => {
  each(cartesian([systems, algorithms]))(
    'success - without nonce - over %s/%s', async (system, algorithm) => {
    const ctx = initBackend(system);
    const [x, { u, v }] = await createDlogPair(ctx);
    const proof = await nizk(ctx, algorithm).proveDlog(x, { u, v });
    const isValid = await nizk(ctx, algorithm).verifyDlog({ u, v }, proof);
    assert.equal(isValid, true);
  });
  each(cartesian([systems, algorithms]))(
    'success - with nonce - over %s/%s', async (system, algorithm) => {
    const ctx = initBackend(system);
    const [x, { u, v }] = await createDlogPair(ctx);
    const nonce = await randomNonce();
    const proof = await nizk(ctx, algorithm).proveDlog(x, { u, v }, nonce);
    const isValid = await nizk(ctx, algorithm).verifyDlog({ u, v }, proof, nonce);
    assert.equal(isValid, true);
  });
  each(systems)('failure - forged secret - over %s', async (system) => {
    const ctx = initBackend(system);
    const [_, { u, v }] = await createDlogPair(ctx);
    const [x, __] = await createDlogPair(ctx);
    const proof = await nizk(ctx, Algorithms.SHA256).proveDlog(x, { u, v });
    const isValid = await nizk(ctx, Algorithms.SHA256).verifyDlog({ u, v }, proof);
    assert.equal(isValid, false);
  });
  each(systems)('failure - forged nonce - over %s', async (system) => {
    const ctx = initBackend(system);
    const [x, { u, v }] = await createDlogPair(ctx);
    const nonce = await randomNonce();
    const proof = await nizk(ctx, Algorithms.SHA256).proveDlog(x, { u, v }, nonce);
    const isValid = await nizk(ctx, Algorithms.SHA256).verifyDlog({ u, v }, proof, await randomNonce());
    assert.equal(isValid, false);
  });
  each(systems)('failure - missing nonce - over %s', async (system) => {
    const ctx = initBackend(system);
    const [x, { u, v }] = await createDlogPair(ctx);
    const nonce = await randomNonce();
    const proof = await nizk(ctx, Algorithms.SHA256).proveDlog(x, { u, v }, nonce);
    const isValid = await nizk(ctx, Algorithms.SHA256).verifyDlog({ u, v }, proof);
    assert.equal(isValid, false);
  });
});
