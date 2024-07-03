import { extractPartialKey } from 'vsslib/keys';
import { SecretPacket } from 'vsslib/dealer';
import { resolveTestConfig } from '../environ';
import { selectPartialKey, createKeySharingSetup } from '../helpers';

const { systems, nrShares, threshold } = resolveTestConfig();


describe('Feldman VSS scheme - success', () => {
  it.each(systems)('success - over %s', async (system) => {
    const { ctx, sharing, privateShares: shares } = await createKeySharingSetup({
      system, nrShares, threshold
    });
    const { packets, commitments } = await sharing.createFeldmanPackets();
    packets.forEach(async (packet: SecretPacket) => {
      const privateShare = await extractPartialKey(ctx, commitments, packet);
      const targetShare = selectPartialKey(privateShare.index, shares);
      expect(await privateShare.equals(targetShare)).toBe(true);
    })
  });
  it.each(systems)('failure - over %s', async (system) => {
    const { ctx, sharing, privateShares: shares } = await createKeySharingSetup({
      system, nrShares, threshold
    });
    const { packets, commitments } = await sharing.createFeldmanPackets();
    const forgedCommitmnets = [
      ...commitments.slice(0, commitments.length - 1),
      await ctx.randomPublic()
    ];
    packets.forEach(async (packet: SecretPacket) => {
      const privateShare = await extractPartialKey(ctx, commitments, packet);
      await expect(
        extractPartialKey(ctx, forgedCommitmnets, packet)
      ).rejects.toThrow(
        'Invalid share'
      );
    })
  });
});
