import { extractPartialKey } from 'vsslib/keys';
import { SecretPacket } from 'vsslib/dealer';
import { randomPublic, isEqualSecret } from 'vsslib/secrets';
import { resolveTestConfig } from '../environ';
import { selectPartialKey, createKeySharingSetup } from '../helpers';

const { systems, nrShares, threshold } = resolveTestConfig();


describe('Pedersen VSS scheme', () => {
  it.each(systems)('success - over %s', async (system) => {
    const { ctx, sharing, partialKeys } = await createKeySharingSetup(system, nrShares, threshold);
    const publicBytes = await randomPublic(ctx);
    const { packets, commitments } = await sharing.createPedersenPackets(publicBytes);
    packets.forEach(async (packet: SecretPacket) => {
      const partialKey = await extractPartialKey(ctx, commitments, packet, publicBytes);
      const targetKey = selectPartialKey(partialKey.index, partialKeys);
      expect(
        await isEqualSecret(ctx, partialKey.secret, targetKey.secret)
      ).toBe(true);
    })
  })
  it.each(systems)('failure - over %s', async (system) => {
    const { ctx, sharing } = await createKeySharingSetup(system, nrShares, threshold);
    const publicBytes = await randomPublic(ctx);
    const { packets, commitments } = await sharing.createPedersenPackets(publicBytes);
    commitments[0] = await randomPublic(ctx);  // tamper first commitment
    packets.forEach(async (packet: SecretPacket) => {
      await expect(extractPartialKey(ctx, commitments, packet, publicBytes)).rejects.toThrow(
        'Invalid share'
      );
    })
  })
})
