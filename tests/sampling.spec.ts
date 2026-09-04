import { initBackend } from 'vsslib';
import { resolveTestConfig } from './environ';

const { systems } = resolveTestConfig();


describe('Scalar sampling', () => {
  it.each(systems)('no reduction bias over %s', async (system) => {
    // Reducing N = 2^(8 * Fp.BYTES) random bits modulo q makes values below
    // N mod q more likely; on jubjub the excess is about 1.4% of the samples
    const ctx = initBackend(system);
    const Fp = ctx.curve.Point.Fp;
    const q = ctx.order;
    const rem = (1n << BigInt(8 * Fp.BYTES)) % q;
    const p = Number((rem * 1_000_000n) / q) / 1_000_000;
    const n = 100_000;
    let below = 0;
    for (let i = 0; i < n; i++) if (await ctx.randomScalar() < rem) below++;
    const sigma = Math.sqrt(n * p * (1 - p));
    expect(Math.abs(below - n * p)).toBeLessThanOrEqual(5 * sigma + 1);
  });
});
