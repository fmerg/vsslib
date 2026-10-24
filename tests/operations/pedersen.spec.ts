import { describe, test, mock } from 'node:test';
import assert from 'node:assert/strict';
import {
  derivePedersenBase,
  createPedersenPackets,
  verifyPedersenCommitments,
  parsePedersenPacket,
  parsePedersenBase,
  clearPedersenBases,
} from 'vsslib/operations/pedersen';
import { initBackend, randomPublic, shareSecret, InvalidInput } from 'vsslib';
import { Group } from 'vsslib/backend';
import type { EcGroup, EcPoint } from 'vsslib/backend';
import { resolveTestConfig } from '../environ';
import { isEqualBuffer, each } from '../utils';
import { fixtures } from '../systems';

const { systems, nrShares, threshold } = resolveTestConfig();


describe('Pedersen VSS scheme', () => {
  each(systems)('success over %s', async (system) => {
    const ctx = initBackend(system);
    const { sharing } = await shareSecret(ctx, nrShares, threshold);
    const pedersenBase = await derivePedersenBase(ctx);
    const { packets, commitments } = await createPedersenPackets(sharing, pedersenBase);
    const secretShares = await sharing.getSecretShares();
    for (const share of secretShares) {
      // Check verification
      const binding = packets[share.index - 1].binding!;
      const isValid = await verifyPedersenCommitments(
        ctx,
        commitments,
        pedersenBase,
        share,
        binding,
        threshold,
      );
      assert.equal(isValid, true);
      // Check parsing
      const packet = await parsePedersenPacket(
        ctx,
        commitments,
        pedersenBase,
        packets[share.index - 1],
        threshold,
      );
      assert.equal(isEqualBuffer(packet.share.value, share.value), true);
    }
  });
  each(systems)('failure over %s', async (system) => {
    const ctx = initBackend(system);
    const { sharing } = await shareSecret(ctx, nrShares, threshold);
    const pedersenBase = await derivePedersenBase(ctx);
    const { packets, commitments } = await createPedersenPackets(sharing, pedersenBase);
    commitments[0] = await randomPublic(ctx);
    const secretShares = await sharing.getSecretShares();
    for (const share of secretShares) {
      // Check verification failure
      const binding = packets[share.index - 1].binding!;
      const verification = verifyPedersenCommitments(
        ctx,
        commitments,
        pedersenBase,
        share,
        binding,
        threshold,
      );
      await assert.rejects(verification, /Invalid share/);
      // Check parsing failure
      const parsed = parsePedersenPacket(
        ctx,
        commitments,
        pedersenBase,
        packets[share.index - 1],
        threshold,
      );
      await assert.rejects(parsed, /Invalid share/);
    }
  });
  each(systems)('commitment count must match threshold over %s', async (system) => {
    // A dealer announcing threshold t but sharing with another degree must be
    // caught: with t + 1 commitments every share verifies, yet t shares cannot
    // reconstruct the secret
    const ctx = initBackend(system);
    const pedersenBase = await derivePedersenBase(ctx);
    for (const actual of [threshold - 1, threshold + 1].filter(t => t > 0)) {
      const { sharing } = await shareSecret(ctx, nrShares + 1, actual);
      const { packets, commitments } = await createPedersenPackets(sharing, pedersenBase);
      for (const packet of packets) {
        await assert.rejects(parsePedersenPacket(ctx, commitments, pedersenBase, packet, threshold), /Invalid number of commitments/);
      }
    }
    const { sharing } = await shareSecret(ctx, nrShares, threshold);
    const { packets, commitments } = await createPedersenPackets(sharing, pedersenBase);
    for (const bad of [0, 1.5, -1]) {
      await assert.rejects(parsePedersenPacket(ctx, commitments, pedersenBase, packets[0], bad), /Threshold must be a positive integer/);
    }
  });
  each(systems)('success with large indexes over %s', async (system) => {
    // index ** j exceeds Number.MAX_SAFE_INTEGER for these parameters
    const ctx = initBackend(system);
    const { sharing } = await shareSecret(ctx, 20, 17);
    const pedersenBase = await derivePedersenBase(ctx);
    const { packets, commitments } = await createPedersenPackets(sharing, pedersenBase);
    for (const packet of packets) {
      assert.notEqual(await parsePedersenPacket(ctx, commitments, pedersenBase, packet, 17), undefined);
    }
  });
})


describe('Pedersen base derivation', () => {
  each(systems)('default base over %s', async (system) => {
    const ctx = initBackend(system);
    const h = await derivePedersenBase(ctx);
    assert.equal(Buffer.from(h).toString('hex'), fixtures[system].defaultPedersenBase);
  });
  each(systems)('deterministic and seed dependent over %s', async (system) => {
    const ctx = initBackend(system);
    const seed = new TextEncoder().encode('session-1');
    const h1 = await derivePedersenBase(ctx, seed);
    const h2 = await derivePedersenBase(ctx, seed);
    const h3 = await derivePedersenBase(ctx, new TextEncoder().encode('session-2'));
    assert.equal(isEqualBuffer(h1, h2), true);
    assert.equal(isEqualBuffer(h1, h3), false);
  });
  each(systems)('prime-order and non-trivial over %s', async (system) => {
    const ctx = initBackend(system);
    const seeds = ['', 'a', 'session-1'].map(s => new TextEncoder().encode(s));
    for (const seed of seeds) {
      // parsePoint rejects points outside the prime-order subgroup
      const h = await ctx.parsePoint(await derivePedersenBase(ctx, seed));
      assert.equal(await h.equals(ctx.neutral), false);
      assert.equal(await h.equals(ctx.generator), false);
    }
  });
});


/** Group over the operations of an elliptic backend under the same system
 * name, as a custom backend could declare */
const custom = (ctx: EcGroup): Group<EcPoint> => {
  class Custom extends Group<EcPoint> {
    randomScalar = ctx.randomScalar;
    randomPoint = ctx.randomPoint;
    validateScalar = ctx.validateScalar;
    validatePoint = ctx.validatePoint;
    exp = ctx.exp;
    operate = ctx.operate;
    invert = ctx.invert;
    bytesToPoint = ctx.bytesToPoint;
    hashToPoint = ctx.hashToPoint;
  }
  return new Custom(ctx.system, ctx.modulus, ctx.order, ctx.generator, ctx.neutral);
}

const seed = (i: number) => Uint8Array.of(i);


describe('Pedersen base cache', () => {
  each(systems)('returns the same base across groups over %s', async (system) => {
    clearPedersenBases();
    const bytes = await derivePedersenBase(initBackend(system));
    const ctx = initBackend(system);
    const precompute = mock.method(ctx, 'precomputeBase');
    const h = await parsePedersenBase(ctx, bytes);
    assert.equal(precompute.mock.callCount(), 1);
    assert.equal(await parsePedersenBase(ctx, bytes), h);
    assert.equal(await parsePedersenBase(initBackend(system), bytes), h);
    assert.equal(precompute.mock.callCount(), 1);
    assert.deepEqual(h.toBytes(), bytes);
    const other = await parsePedersenBase(ctx, await derivePedersenBase(ctx, seed(1)));
    assert.notEqual(other, h);
  });
  each(systems)('never caches invalid bases over %s', async (system) => {
    clearPedersenBases();
    const ctx = initBackend(system);
    const parse = mock.method(ctx, 'parsePoint');
    const invalid = [
      ctx.neutral.toBytes(),
      ctx.generator.toBytes(),
      Uint8Array.of(...ctx.generator.toBytes(), 0),
    ];
    for (const bytes of invalid) {
      for (let i = 0; i < 2; i++) {
        await assert.rejects(parsePedersenBase(ctx, bytes), InvalidInput);
      }
    }
    assert.equal(parse.mock.callCount(), 2 * invalid.length);
  });
  each(systems)('evicts the least recently used base over %s', async (system) => {
    clearPedersenBases();
    const ctx = initBackend(system);
    const bases = [];
    for (let i = 0; i < 10; i++) bases.push(await derivePedersenBase(ctx, seed(i)));
    for (const bytes of bases.slice(0, 8)) await parsePedersenBase(ctx, bytes);
    const parse = mock.method(ctx, 'parsePoint');
    // A hit on the oldest makes the second oldest the next to go
    await parsePedersenBase(ctx, bases[0]);
    await parsePedersenBase(ctx, bases[8]);
    assert.equal(parse.mock.callCount(), 1);
    await parsePedersenBase(ctx, bases[0]);
    assert.equal(parse.mock.callCount(), 1);
    await parsePedersenBase(ctx, bases[1]);
    assert.equal(parse.mock.callCount(), 2);
    // That reparse evicted bases[2], the least recently used by then
    await parsePedersenBase(ctx, bases[2]);
    assert.equal(parse.mock.callCount(), 3);
  });
  each(systems)('keeps custom groups apart over %s', async (system) => {
    clearPedersenBases();
    const ctx = initBackend(system);
    const other = custom(ctx);
    const bytes = await derivePedersenBase(ctx);
    const h = await parsePedersenBase(ctx, bytes);
    const parse = mock.method(other, 'parsePoint');
    assert.notEqual(await parsePedersenBase(other, bytes), h);
    assert.equal(parse.mock.callCount(), 1);
  });
  test('keeps systems apart', async () => {
    // A base whose encoding is valid on both ed25519 and ristretto255
    clearPedersenBases();
    const [ed, ristretto] = [initBackend('ed25519'), initBackend('ristretto255')];
    let bytes;
    for (let i = 0; i < 256 && !bytes; i++) {
      const candidate = await derivePedersenBase(ed, seed(i));
      try {
        await ristretto.parsePoint(candidate);
        bytes = candidate;
      } catch { /* not a ristretto255 encoding */ }
    }
    assert.ok(bytes);
    const h = await parsePedersenBase(ed, bytes);
    const parse = mock.method(ristretto, 'parsePoint');
    const g = await parsePedersenBase(ristretto, bytes);
    assert.equal(parse.mock.callCount(), 1);
    assert.notEqual(g, h);
    assert.equal(await parsePedersenBase(ed, bytes), h);
  });
});
