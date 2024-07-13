import { extractPartialKey } from 'vsslib/keys';
import { SecretPacket } from 'vsslib/dealer';
import { isEqualSecret } from 'vsslib/secrets';
import { resolveTestConfig } from '../environ';
import { selectPartialKey, createKeySharingSetup } from '../helpers';

const { systems, nrShares, threshold } = resolveTestConfig();


describe('Pedersen VSS scheme', () => {
  it.each(systems)('success - over %s', async (system) => {
    const { ctx, sharing, privateShares: shares } = await createKeySharingSetup({
      system, nrShares, threshold
    });
    const publicBytes = await ctx.randomPublic();
    const { packets, commitments } = await sharing.createPedersenPackets(
      publicBytes
    );
    packets.forEach(async (packet: SecretPacket) => {
      const privateShare = await extractPartialKey(
        ctx, commitments, packet, publicBytes,
      );
      const targetShare = selectPartialKey(privateShare.index, shares);
      expect(
        await isEqualSecret(ctx, privateShare.secret, targetShare.secret)
      ).toBe(true);
    })
  })
  it.each(systems)('failure - over %s', async (system) => {
    const { ctx, sharing, privateShares: shares } = await createKeySharingSetup({
      system, nrShares, threshold
    });
    const publicBytes = await ctx.randomPublic();
    const { packets, commitments } = await sharing.createPedersenPackets(
      publicBytes
    );
    const forgedCommitments = [
      ...commitments.slice(0, commitments.length - 1),
      await ctx.randomPublic()
    ];
    packets.forEach(async (packet: SecretPacket) => {
      await expect(
        extractPartialKey(
          ctx, forgedCommitments, packet, publicBytes,
        )
      ).rejects.toThrow(
        'Invalid share'
      );
    })
  })
})
