import { initBackend } from 'vsslib/backend';
import { nizk } from 'vsslib/nizk';
import { Algorithms } from 'vsslib/enums';
import { resolveTestConfig } from '../environ';

const { systems } = resolveTestConfig();

const bytes = (s: string) => new TextEncoder().encode(s);


describe('Fiat-Shamir challenge input', () => {
  it.each(systems)('extras and nonce boundaries are unambiguous over %s', async (system) => {
    const ctx = initBackend(system);
    const g = ctx.generator;
    const x = await ctx.randomScalar();
    const v = await ctx.exp(g, x);
    const protocol = nizk(ctx, Algorithms.DEFAULT);
    const relation = { us: [[g]], vs: [v] };
    const proof = await protocol.proveLinear([x], relation, bytes('nonce'), [bytes('ab'), bytes('c')]);
    expect(await protocol.verifyLinear(relation, proof, bytes('nonce'), [bytes('ab'), bytes('c')])).toBe(true);
    const collisions: [Uint8Array | undefined, Uint8Array[]][] = [
      [bytes('nonce'), [bytes('a'), bytes('bc')]],
      [bytes('nonce'), [bytes('abc')]],
      [bytes('cnonce'), [bytes('ab')]],
      [undefined, [bytes('ab'), bytes('cnonce')]],
    ];
    for (const [nonce, extras] of collisions) {
      expect(await protocol.verifyLinear(relation, proof, nonce, extras)).toBe(false);
    }
  });
  it.each(systems)('proofs are bound to their type over %s', async (system) => {
    const ctx = initBackend(system);
    const g = ctx.generator;
    const x = await ctx.randomScalar();
    const v = await ctx.exp(g, x);
    const protocol = nizk(ctx, Algorithms.DEFAULT);
    const proof = await protocol.proveDlog(x, { u: g, v });
    expect(await protocol.verifyDlog({ u: g, v }, proof)).toBe(true);
    expect(await protocol.verifyLinear({ us: [[g]], vs: [v] }, proof)).toBe(false);
  });
});
