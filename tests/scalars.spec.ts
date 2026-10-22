import { describe } from 'node:test';
import assert from 'node:assert/strict';
import { each } from './utils';
import { initBackend, parseScalar, InvalidInput } from 'vsslib';
import { nizk } from 'vsslib/nizk';
import { Algorithms } from 'vsslib/enums';
import { intToLeBytes, leBytesToInt } from 'vsslib/arith';
import { resolveTestConfig } from './environ';

const { systems } = resolveTestConfig();


describe('Strict scalar decoding', () => {
  each(systems)('non-canonical encodings are rejected over %s', async (system) => {
    const ctx = initBackend(system);
    const { order: q, scalarBytes: len } = ctx;
    const s = await ctx.randomScalar();
    assert.equal(await parseScalar(ctx, intToLeBytes(s, len)), s);
    // s + q fits in scalarBytes whenever 2q <= 2^(8 * scalarBytes)
    const sameLength = s + q < (1n << BigInt(8 * len)) ? [intToLeBytes(s + q, len)] : [];
    const encodings = [
      ...sameLength,
      intToLeBytes(s + q, len + 1),
      intToLeBytes(s, len + 1),
      intToLeBytes(s, len).slice(0, len - 1),
      intToLeBytes(q, len),
    ];
    for (const bytes of encodings) {
      await assert.rejects(parseScalar(ctx, bytes), InvalidInput);
    }
  });
  each(systems)('proofs are not malleable over %s', async (system) => {
    const ctx = initBackend(system);
    const { order: q, scalarBytes: len } = ctx;
    const g = ctx.generator;
    const x = await ctx.randomScalar();
    const v = await ctx.exp(g, x);
    const protocol = nizk(ctx, Algorithms.DEFAULT);
    const proof = await protocol.proveDlog(x, { u: g, v });
    assert.equal(await protocol.verifyDlog({ u: g, v }, proof), true);
    const r = leBytesToInt(proof.response[0]);
    const mauled = { ...proof, response: [intToLeBytes(r + q, len + 1)] };
    await assert.rejects(protocol.verifyDlog({ u: g, v }, mauled), InvalidInput);
  });
});
