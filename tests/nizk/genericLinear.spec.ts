import { Algorithms } from '../../src/enums';
import { initBackend } from '../../src/backend';
import { randomNonce } from '../../src/crypto';
import { cartesian } from '../utils';
import { createGenericLinear } from './helpers';
import { resolveTestConfig } from '../environ';
import nizk from '../../src/nizk';

let { systems, algorithms } = resolveTestConfig();


describe('NIZK proof of generik linear relation', () => {
  it.each(cartesian([systems, algorithms]))(
    'success - without nonce - over %s/%s', async (system, algorithm) => {
    const ctx = initBackend(system);
    const [witness, relation] = await createGenericLinear(ctx, { m: 5, n: 3 });
    const proof = await nizk(ctx, algorithm).proveLinear(witness, relation);
    const valid = await nizk(ctx, algorithm).verifyLinear(relation, proof);
    expect(valid).toBe(true);
  });
  it.each(cartesian([systems, algorithms]))(
    'success - with nonce - over %s/%s', async (system, algorithm) => {
    const ctx = initBackend(system);
    const nonce = await randomNonce();
    const [witness, relation] = await createGenericLinear(ctx, { m: 5, n: 3 });
    const proof = await nizk(ctx, algorithm).proveLinear(witness, relation, nonce);
    const valid = await nizk(ctx, algorithm).verifyLinear(relation, proof, nonce);
    expect(valid).toBe(true);
  });
  it.each(systems)('failure - forged witness - over %s', async (system) => {
    const ctx = initBackend(system);
    const [_, relation] = await createGenericLinear(ctx, { m: 5, n: 3 });
    const [witness, __] = await createGenericLinear(ctx, { m: 5, n: 3 });
    const proof = await nizk(ctx, Algorithms.SHA256).proveLinear(witness, relation);
    const valid = await nizk(ctx, Algorithms.SHA256).verifyLinear(relation, proof);
    expect(valid).toBe(false);
  });
  it.each(systems)('failure - forged nonce - over %s', async (system) => {
    const ctx = initBackend(system);
    const [witness, relation] = await createGenericLinear(ctx, { m: 5, n: 3 });
    const nonce = await randomNonce();
    const proof = await nizk(ctx, Algorithms.SHA256).proveLinear(witness, relation, nonce);
    const valid = await nizk(ctx, Algorithms.SHA256).verifyLinear(relation, proof, await randomNonce());
    expect(valid).toBe(false);
  });
  it.each(systems)('failure - missing nonce - over %s', async (system) => {
    const ctx = initBackend(system);
    const [witness, relation] = await createGenericLinear(ctx, { m: 5, n: 3 });
    const nonce = await randomNonce();
    const proof = await nizk(ctx, Algorithms.SHA256).proveLinear(witness, relation, nonce);
    const valid = await nizk(ctx, Algorithms.SHA256).verifyLinear(relation, proof);
    expect(valid).toBe(false);
  });
});
