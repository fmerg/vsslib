import { PrivateKeyShare } from '../../src/keys';
import { SecretSharePacket } from '../../src/shamir';
import { resolveTestConfig } from '../environ';
import { selectPrivateKeyShare, createKeySharingSetup } from '../helpers';

const { systems, nrShares, threshold } = resolveTestConfig();


describe('Feldman verification scheme - success', () => {
  it.each(systems)('over %s', async (system) => {
    const { ctx, sharing, privateShares: shares } = await createKeySharingSetup({
      system, nrShares, threshold
    });
    const { packets, commitments } = await sharing.createFeldmanPackets();
    packets.forEach(async (packet: SecretSharePacket) => {
      const privateShare = await PrivateKeyShare.fromFeldmanPacket(ctx, commitments, packet);
      const targetShare = selectPrivateKeyShare(privateShare.index, shares);
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
    packets.forEach(async (packet: SecretSharePacket) => {
      const privateShare = await PrivateKeyShare.fromFeldmanPacket(ctx, commitments, packet);
      await expect(
        PrivateKeyShare.fromFeldmanPacket(ctx, forgedCommitmnets, packet)
      ).rejects.toThrow(
        'Invalid share'
      );
    })
  });
});
