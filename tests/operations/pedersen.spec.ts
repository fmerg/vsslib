import { describe } from 'node:test';
import assert from 'node:assert/strict';
import {
  derivePedersenBase,
  createPedersenPackets,
  verifyPedersenCommitments,
  parsePedersenPacket,
} from 'vsslib/operations/pedersen';
import { initBackend, randomPublic, shareSecret } from 'vsslib';
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
    assert.deepEqual(Buffer.from(h).toString('hex'), fixtures[system].defaultPedersenBase);
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
