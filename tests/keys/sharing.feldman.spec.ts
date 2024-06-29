import { PartialKey } from '../../src/keys';
import { SecretPacket } from '../../src/dealer';
import { resolveTestConfig } from '../environ';
import { selectPartialKey, createKeySharingSetup } from '../helpers';

const { systems, nrShares, threshold } = resolveTestConfig();


describe('Feldman verification scheme - success', () => {
  it.each(systems)('over %s', async (system) => {
    const { ctx, sharing, privateShares: shares } = await createKeySharingSetup({
      system, nrShares, threshold
    });
    const { packets, commitments } = await sharing.createFeldmanPackets();
    packets.forEach(async (packet: SecretPacket) => {
      const privateShare = await PartialKey.fromFeldmanPacket(ctx, commitments, packet);
      const targetShare = selectPartialKey(privateShare.index, shares);
      expect(await privateShare.equals(targetShare)).toBe(true);
    })
  });
});

describe('Feldman verification scheme - failure', () => {
  it.each(systems)('over %s', async (system) => {
    const { ctx, sharing, privateShares: shares } = await createKeySharingSetup({
      system, nrShares, threshold
    });
    const { packets, commitments } = await sharing.createFeldmanPackets();
    const forgedCommitmnets = [
      ...commitments.slice(0, commitments.length - 1),
      (await ctx.randomPoint()).toBytes()
    ];
    packets.forEach(async (packet: SecretPacket) => {
      const privateShare = await PartialKey.fromFeldmanPacket(ctx, commitments, packet);
      await expect(
        PartialKey.fromFeldmanPacket(ctx, forgedCommitmnets, packet)
      ).rejects.toThrow(
        'Invalid share'
      );
    })
  });
});
