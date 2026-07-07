import { initBackend } from 'vsslib/backend';
import { randomSecret, randomPublic } from 'vsslib/secrets';
import { shareSecret, ShamirSharing } from 'vsslib/dealer';
import { SecretShare } from 'vsslib/types';
import { verifyPedersenCommitments, parsePedersenPacket } from 'vsslib/shareholder';
import { resolveTestConfig } from '../environ';
import { intToLeBytes } from 'vsslib/arith';
import { isEqualBuffer } from '../utils';

let { systems, nrShares, threshold } = resolveTestConfig();


describe('Pedersen VSS scheme', () => {
  it.each(systems)('success over %s', async (system) => {
    const ctx = initBackend(system);
    const { secret, sharing } = await shareSecret(ctx, nrShares, threshold);
    const pedersenBase = await randomPublic(ctx);
    const { packets, commitments } = await sharing.createPedersenPackets(pedersenBase);
    const secretShares = await sharing.getSecretShares();
    secretShares.forEach(async (share: SecretShare) => {
      // Check verification
      const binding = packets[share.index - 1].binding!;
      const isValid = await verifyPedersenCommitments(
        ctx,
        commitments,
        pedersenBase,
        share,
        binding,
      );
      expect(isValid).toBe(true);
      // Check parsing
      const packet = await parsePedersenPacket(
        ctx,
        commitments,
        pedersenBase,
        packets[share.index - 1]
      );
      expect(isEqualBuffer(packet.share.value, share.value)).toBe(true);
    });
  });
  it.each(systems)('failure over %s', async (system) => {
    const ctx = initBackend(system);
    const { secret, sharing } = await shareSecret(ctx, nrShares, threshold);
    const pedersenBase = await randomPublic(ctx);
    const { packets, commitments } = await sharing.createPedersenPackets(pedersenBase);
    commitments[0] = await randomPublic(ctx);
    const secretShares = await sharing.getSecretShares();
    secretShares.forEach(async (share: SecretShare) => {
      // Check verification failure
      const binding = packets[share.index - 1].binding!;
      const verification = verifyPedersenCommitments(
        ctx,
        commitments,
        pedersenBase,
        share,
        binding,
      );
      await expect(verification).rejects.toThrow('Invalid share');
      // Check parsing failure
      const parsed = parsePedersenPacket(
        ctx,
        commitments,
        pedersenBase,
        packets[share.index - 1]
      );
      await expect(parsed).rejects.toThrow('Invalid share');
    });
  });
  it.each(systems)('success with large indexes over %s', async (system) => {
    // index ** j exceeds Number.MAX_SAFE_INTEGER for these parameters
    const ctx = initBackend(system);
    const { sharing } = await shareSecret(ctx, 20, 17);
    const pedersenBase = await randomPublic(ctx);
    const { packets, commitments } = await sharing.createPedersenPackets(pedersenBase);
    for (const packet of packets) {
      await expect(
        parsePedersenPacket(ctx, commitments, pedersenBase, packet)
      ).resolves.toBeDefined();
    }
  });
})
