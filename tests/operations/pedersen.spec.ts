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
import type { EcPoint } from 'vsslib/backend';
import { resolveTestConfig } from '../environ';
import { isEqualBuffer, each } from '../utils';
import { fixtures } from '../systems';
import { inheriting, fixRandomScalarAt } from '../helpers';

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
  each(systems)('vanished top coefficient over %s', async (system) => {
    // The sharing polynomial drops to degree 1, yet the dealing keeps threshold
    // commitments
    const ctx = initBackend(system);
    const pedersenBase = await derivePedersenBase(ctx);
    const secret = await ctx.generateSecret();
    const random = fixRandomScalarAt(ctx, 1);
    const { sharing } = await shareSecret(ctx, 5, 3, secret);
    random.mock.restore();
    assert.equal(sharing.polynomial.degree, 1);
    const { packets, commitments } = await createPedersenPackets(sharing, pedersenBase);
    assert.equal(commitments.length, 3);
    for (const packet of packets) {
      assert.notEqual(await parsePedersenPacket(ctx, commitments, pedersenBase, packet, 3), undefined);
    }
  });
  each(systems)('vanished top binding coefficient over %s', async (system) => {
    // The binding polynomial is sampled first, by the first threshold calls of
    // randomScalar; its top coefficient used to be read past the end
    const ctx = initBackend(system);
    const pedersenBase = await derivePedersenBase(ctx);
    const { sharing } = await shareSecret(ctx, 5, 3);
    assert.equal(sharing.polynomial.degree, 2);
    const random = fixRandomScalarAt(ctx, 2);
    const { packets, commitments } = await createPedersenPackets(sharing, pedersenBase);
    random.mock.restore();
    assert.equal(commitments.length, 3);
    for (const packet of packets) {
      assert.notEqual(await parsePedersenPacket(ctx, commitments, pedersenBase, packet, 3), undefined);
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


const seed = (i: number) => Uint8Array.of(i);


describe('Pedersen base cache', () => {
  each(systems)('returns the same base across groups over %s', async (system) => {
    clearPedersenBases();
    const bytes = await derivePedersenBase(initBackend(system));
    const ctx = initBackend(system);
    const precompute = mock.method(ctx, 'precomputeBase');
    const h = await parsePedersenBase(ctx, bytes);
    // Prepared on the second use only, so that a single use costs no more
    assert.equal(precompute.mock.callCount(), 0);
    assert.equal(await parsePedersenBase(ctx, bytes), h);
    assert.equal(precompute.mock.callCount(), 1);
    assert.equal(await parsePedersenBase(initBackend(system), bytes), h);
    assert.equal(await parsePedersenBase(ctx, bytes), h);
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
    // Other than bytes, rejected as before the cache
    for (const value of ['00', [1, 2, 3], undefined]) {
      await assert.rejects(parsePedersenBase(ctx, value as unknown as Uint8Array), InvalidInput);
    }
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
    const other = inheriting(ctx);
    const bytes = await derivePedersenBase(ctx);
    const h = await parsePedersenBase(ctx, bytes);
    const parse = mock.method(other, 'parsePoint');
    assert.notEqual(await parsePedersenBase(other, bytes), h);
    assert.equal(parse.mock.callCount(), 1);
  });
  each(systems)('keeps groups of one class with other parameters apart over %s', async (system) => {
    clearPedersenBases();
    const ctx = initBackend(system);
    const lhs = inheriting(ctx);
    // Same class, other generator
    const Inheriting = lhs.constructor as new (...args: unknown[]) => Group<EcPoint>;
    const generator = await ctx.exp(ctx.generator, BigInt(2));
    const rhs = new Inheriting(ctx.system, ctx.modulus, ctx.order, generator, ctx.neutral);
    const bytes = await derivePedersenBase(ctx);
    const h = await parsePedersenBase(lhs, bytes);
    const parse = mock.method(rhs, 'parsePoint');
    assert.notEqual(await parsePedersenBase(rhs, bytes), h);
    assert.equal(parse.mock.callCount(), 1);
  });
  each(systems)('keeps a single entry under concurrent calls over %s', async (system) => {
    clearPedersenBases();
    const ctx = initBackend(system);
    const [b1, b2] = [await derivePedersenBase(ctx, seed(1)), await derivePedersenBase(ctx, seed(2))];
    // Concurrent misses parse each, but all receive the first cached point
    const points = await Promise.all([b1, b1, b1, b2].map(b => parsePedersenBase(ctx, b)));
    assert.ok(points.slice(1, 3).every(point => point === points[0]));
    const parse = mock.method(ctx, 'parsePoint');
    assert.equal(await parsePedersenBase(ctx, b1), points[0]);
    // Both keys survive, although each call found no cache for the class
    assert.equal(await parsePedersenBase(ctx, b2), points[3]);
    assert.equal(parse.mock.callCount(), 0);
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
