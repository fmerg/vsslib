import { initBackend } from 'vsslib/backend';
import { randomSecret, randomPublic, derivePedersenBase } from 'vsslib/secrets';
import { shareSecret, ShamirSharing } from 'vsslib/dealer';
import { SecretShare } from 'vsslib/types';
import { verifyPedersenCommitments, parsePedersenPacket } from 'vsslib/shareholder';
import { resolveTestConfig } from '../environ';
import { intToLeBytes } from 'vsslib/arith';
import { isEqualBuffer } from '../utils';
import { fixtures } from '../systems';

let { systems, nrShares, threshold } = resolveTestConfig();


describe('Pedersen VSS scheme', () => {
  it.each(systems)('success over %s', async (system) => {
    const ctx = initBackend(system);
    const { secret, sharing } = await shareSecret(ctx, nrShares, threshold);
    const pedersenBase = await derivePedersenBase(ctx);
    const { packets, commitments } = await sharing.createPedersenPackets(pedersenBase);
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
      expect(isValid).toBe(true);
      // Check parsing
      const packet = await parsePedersenPacket(
        ctx,
        commitments,
        pedersenBase,
        packets[share.index - 1],
        threshold,
      );
      expect(isEqualBuffer(packet.share.value, share.value)).toBe(true);
    }
  });
  it.each(systems)('failure over %s', async (system) => {
    const ctx = initBackend(system);
    const { secret, sharing } = await shareSecret(ctx, nrShares, threshold);
    const pedersenBase = await derivePedersenBase(ctx);
    const { packets, commitments } = await sharing.createPedersenPackets(pedersenBase);
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
      await expect(verification).rejects.toThrow('Invalid share');
      // Check parsing failure
      const parsed = parsePedersenPacket(
        ctx,
        commitments,
        pedersenBase,
        packets[share.index - 1],
        threshold,
      );
      await expect(parsed).rejects.toThrow('Invalid share');
    }
  });
  it.each(systems)('commitment count must match threshold over %s', async (system) => {
    // A dealer announcing threshold t but sharing with another degree must be
    // caught: with t + 1 commitments every share verifies, yet t shares cannot
    // reconstruct the secret
    const ctx = initBackend(system);
    const pedersenBase = await derivePedersenBase(ctx);
    for (const actual of [threshold - 1, threshold + 1].filter(t => t > 0)) {
      const { sharing } = await shareSecret(ctx, nrShares + 1, actual);
      const { packets, commitments } = await sharing.createPedersenPackets(pedersenBase);
      for (const packet of packets) {
        await expect(
          parsePedersenPacket(ctx, commitments, pedersenBase, packet, threshold)
        ).rejects.toThrow('Invalid number of commitments');
      }
    }
    const { sharing } = await shareSecret(ctx, nrShares, threshold);
    const { packets, commitments } = await sharing.createPedersenPackets(pedersenBase);
    for (const bad of [0, 1.5, -1]) {
      await expect(
        parsePedersenPacket(ctx, commitments, pedersenBase, packets[0], bad)
      ).rejects.toThrow('Threshold must be a positive integer');
    }
  });
  it.each(systems)('success with large indexes over %s', async (system) => {
    // index ** j exceeds Number.MAX_SAFE_INTEGER for these parameters
    const ctx = initBackend(system);
    const { sharing } = await shareSecret(ctx, 20, 17);
    const pedersenBase = await derivePedersenBase(ctx);
    const { packets, commitments } = await sharing.createPedersenPackets(pedersenBase);
    for (const packet of packets) {
      await expect(
        parsePedersenPacket(ctx, commitments, pedersenBase, packet, 17)
      ).resolves.toBeDefined();
    }
  });
})


describe('Pedersen base derivation', () => {
  it.each(systems)('default base over %s', async (system) => {
    const ctx = initBackend(system);
    const h = await derivePedersenBase(ctx);
    expect(Buffer.from(h).toString('hex')).toEqual(fixtures[system].defaultPedersenBase);
  });
  it.each(systems)('deterministic and seed dependent over %s', async (system) => {
    const ctx = initBackend(system);
    const seed = new TextEncoder().encode('session-1');
    const h1 = await derivePedersenBase(ctx, seed);
    const h2 = await derivePedersenBase(ctx, seed);
    const h3 = await derivePedersenBase(ctx, new TextEncoder().encode('session-2'));
    expect(isEqualBuffer(h1, h2)).toBe(true);
    expect(isEqualBuffer(h1, h3)).toBe(false);
  });
  it.each(systems)('prime-order and non-trivial over %s', async (system) => {
    const ctx = initBackend(system);
    const seeds = ['', 'a', 'session-1'].map(s => new TextEncoder().encode(s));
    for (const seed of seeds) {
      // parsePoint rejects points outside the prime-order subgroup
      const h = await ctx.parsePoint(await derivePedersenBase(ctx, seed));
      expect(await h.equals(ctx.neutral)).toBe(false);
      expect(await h.equals(ctx.generator)).toBe(false);
    }
  });
});
