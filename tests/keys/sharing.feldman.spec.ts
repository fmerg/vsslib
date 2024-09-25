import { SecretPacket } from 'vsslib/dealer';
import { parsePartialKey } from 'vsslib/shareholder';
import { randomPublic, isEqualSecret } from 'vsslib/secrets';
import { resolveTestConfig } from '../environ';
import { selectPartialKey, createKeySharingSetup } from '../helpers';

const { systems, nrShares, threshold } = resolveTestConfig();


describe('Feldman VSS scheme - success', () => {
  it.each(systems)('success - over %s', async (system) => {
    const { ctx, sharing, partialKeys } = await createKeySharingSetup(system, nrShares, threshold);
    const { packets, commitments } = await sharing.createFeldmanPackets();
    packets.forEach(async (packet: SecretPacket) => {
      const partialKey = await parsePartialKey(ctx, commitments, packet);
      const targetKey = selectPartialKey(partialKey.index, partialKeys);
      expect(
        await isEqualSecret(ctx, partialKey.secret, targetKey.secret)
      ).toBe(true);
    })
  });
  it.each(systems)('failure - over %s', async (system) => {
    const { ctx, sharing } = await createKeySharingSetup(system, nrShares, threshold);
    const { packets, commitments } = await sharing.createFeldmanPackets();
    commitments[0] = await randomPublic(ctx);  // tamper first commitment
    packets.forEach(async (packet: SecretPacket) => {
      await expect(parsePartialKey(ctx, commitments, packet)).rejects.toThrow(
        'Invalid share'
      );
    })
  });
});
