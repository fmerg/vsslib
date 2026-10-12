import { describe, mock } from 'node:test';
import assert from 'node:assert/strict';
import { each } from './utils';
import { initBackend } from 'vsslib';
import { resolveTestConfig } from './environ';

const { systems } = resolveTestConfig();


describe('Scalar sampling', () => {
  each(systems)('no reduction bias over %s', async (system) => {
    // Reducing N = 2^(8 * fieldBytes) random bits modulo q makes values below
    // N mod q more likely; on jubjub the excess is about 1.4% of the samples
    const ctx = initBackend(system);
    const fieldBytes = Math.ceil(ctx.modulus.toString(2).length / 8);
    const q = ctx.order;
    const rem = (1n << BigInt(8 * fieldBytes)) % q;
    const p = Number((rem * 1_000_000n) / q) / 1_000_000;
    const n = 100_000;
    let below = 0;
    for (let i = 0; i < n; i++) if (await ctx.randomScalar() < rem) below++;
    const sigma = Math.sqrt(n * p * (1 - p));
    assert.ok(Math.abs(below - n * p) <= 5 * sigma + 1);
  });
  each(systems)('random bytes are wiped after sampling over %s', async (system) => {
    // The bytes determine the scalar, which may be a secret or a nonce
    const ctx = initBackend(system);
    const sampled: Uint8Array[] = [];
    // noble's randomBytes returns the array that getRandomValues fills
    const getRandomValues = crypto.getRandomValues.bind(crypto);
    const spy = mock.method(crypto, 'getRandomValues', <T extends ArrayBufferView<ArrayBuffer>>(array: T) => {
      sampled.push(getRandomValues(array) as unknown as Uint8Array);
      return array;
    });
    try {
      await ctx.randomScalar();
    } finally {
      spy.mock.restore();
    }
    assert.equal(sampled.length, 1);
    assert.deepEqual(sampled[0], new Uint8Array(ctx.scalarBytes + 16));
  });
});
