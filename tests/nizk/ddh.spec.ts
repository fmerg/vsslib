import { describe } from 'node:test';
import assert from 'node:assert/strict';
import { each } from '../utils';
import { Algorithms } from 'vsslib/enums';
import { initBackend } from 'vsslib/backend';
import { randomNonce } from 'vsslib/random';
import { cartesian } from '../utils';
import { createDDHTuple } from './helpers';
import { resolveTestConfig } from '../environ';

import { nizk } from 'vsslib/nizk';

const { systems, algorithms } = resolveTestConfig();


describe('NIZK DDH proof (Chaum-Pedersen protocol)', () => {
  each(cartesian([systems, algorithms]))(
    'success - without nonce - over %s/%s', async (system, algorithm) => {
    const ctx = initBackend(system);
    const [z, { u, v, w }] = await createDDHTuple(ctx);
    const proof = await nizk(ctx, algorithm).proveDDH(z, { u, v, w });
    const isValid = await nizk(ctx, algorithm).verifyDDH({ u, v, w }, proof);
    assert.equal(isValid, true);
  });
  each(cartesian([systems, algorithms]))(
    'success - with nonce - over %s/%s', async (system, algorithm) => {
    const ctx = initBackend(system);
    const [z, { u, v, w }] = await createDDHTuple(ctx);
    const nonce = await randomNonce();
    const proof = await nizk(ctx, algorithm).proveDDH(z, { u, v, w }, nonce);
    const isValid = await nizk(ctx, algorithm).verifyDDH({ u, v, w }, proof, nonce);
    assert.equal(isValid, true);
  });
  each(systems)('failure - forged secret - over %s', async (system) => {
    const ctx = initBackend(system);
    const [_, { u, v, w }] = await createDDHTuple(ctx);
    const [z, __] = await createDDHTuple(ctx);
    const proof = await nizk(ctx, Algorithms.SHA256).proveDDH(z, { u, v, w })
    const isValid = await nizk(ctx, Algorithms.SHA256).verifyDDH({ u, v, w }, proof);
    assert.equal(isValid, false);
  });
  each(systems)('failure - forged nonce - over %s', async (system) => {
    const ctx = initBackend(system);
    const [z, { u, v, w }] = await createDDHTuple(ctx);
    const nonce = await randomNonce();
    const proof = await nizk(ctx, Algorithms.SHA256).proveDDH(z, { u, v, w }, nonce);
    const isValid = await nizk(ctx, Algorithms.SHA256).verifyDDH({ u, v, w }, proof, await randomNonce());
    assert.equal(isValid, false);
  });
  each(systems)('failure - missing nonce - over %s', async (system) => {
    const ctx = initBackend(system);
    const [z, { u, v, w }] = await createDDHTuple(ctx);
    const nonce = await randomNonce();
    const proof = await nizk(ctx, Algorithms.SHA256).proveDDH(z, { u, v, w }, nonce);
    const isValid = await nizk(ctx, Algorithms.SHA256).verifyDDH({ u, v, w }, proof);
    assert.equal(isValid, false);
  });
});
