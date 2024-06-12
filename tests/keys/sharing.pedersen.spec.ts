import { PrivateKeyShare, PublicKeyShare } from '../../src/keys';
import { SecretSharePacket } from '../../src/shamir';
import { resolveTestConfig } from '../environ';
import { selectPrivateKeyShare, createKeySharingSetup } from '../helpers';

const { systems, nrShares, threshold } = resolveTestConfig();


describe('Pedersen verification scheme - success', () => {
  it.each(systems)('over %s', async (system) => {
    const { ctx, sharing, privateShares: shares } = await createKeySharingSetup({
      system, nrShares, threshold
    });
    const publicBytes = (await ctx.randomPoint()).toBytes();
    const { packets, commitments } = await sharing.createPedersenPackets(
      publicBytes
    );
    packets.forEach(async (packet: SecretSharePacket) => {
      const privateShare = await PrivateKeyShare.fromPedersenPacket(
        ctx,
        commitments,
        publicBytes,
        packet
      );
      const targetShare = selectPrivateKeyShare(privateShare.index, shares);
      expect(await privateShare.equals(targetShare)).toBe(true);
    })
  })
});

describe('Pedersen verification scheme - failure', () => {
  it.each(systems)('over %s', async (system) => {
    const { ctx, sharing, privateShares: shares } = await createKeySharingSetup({
      system, nrShares, threshold
    });
    const publicBytes = (await ctx.randomPoint()).toBytes();
    const { packets, commitments } = await sharing.createPedersenPackets(
      publicBytes
    );
    const forgedCommitmnets = [
      ...commitments.slice(0, commitments.length - 1),
      (await ctx.randomPoint()).toBytes()
    ];
    packets.forEach(async (packet: SecretSharePacket) => {
      await expect(
        PrivateKeyShare.fromPedersenPacket(
          ctx,
          forgedCommitmnets,
          publicBytes,
          packet,
        )
      ).rejects.toThrow(
        'Invalid share'
      );
    })
  })
});
