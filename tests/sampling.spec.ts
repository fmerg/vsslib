import * as nobleUtils from '@noble/hashes/utils.js';
import { initBackend } from 'vsslib';
import { resolveTestConfig } from './environ';

const { systems } = resolveTestConfig();


describe('Scalar sampling', () => {
  it.each(systems)('no reduction bias over %s', async (system) => {
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
    expect(Math.abs(below - n * p)).toBeLessThanOrEqual(5 * sigma + 1);
  });
  it.each(systems)('random bytes are wiped after sampling over %s', async (system) => {
    // The bytes determine the scalar, which may be a secret or a nonce
    const ctx = initBackend(system);
    const sampled: Uint8Array[] = [];
    const randomBytes = nobleUtils.randomBytes;
    const spy = jest.spyOn(nobleUtils, 'randomBytes').mockImplementation((len) => {
      const bytes = randomBytes(len);
      sampled.push(bytes);
      return bytes;
    });
    try {
      await ctx.randomScalar();
    } finally {
      spy.mockRestore();
    }
    expect(sampled).toHaveLength(1);
    expect(sampled[0]).toEqual(new Uint8Array(ctx.scalarBytes + 16));
  });
});
