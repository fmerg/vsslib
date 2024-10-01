import { initBackend } from 'vsslib/backend';
import { randomPublic } from 'vsslib/secrets';
import { shareSecret, SecretShare, ShamirSharing } from 'vsslib/dealer';
import { verifyFeldmanCommitments, parseFeldmanPacket } from 'vsslib/shareholder';
import { resolveTestConfig } from '../environ';
import { isEqualBuffer } from '../utils';

let { systems, nrShares, threshold } = resolveTestConfig();


describe('Feldman VSS scheme', () => {
  it.each(systems)('success over %s', async (system) => {
    const ctx = initBackend(system);
    const { secret, sharing } = await shareSecret(ctx, nrShares, threshold);
    const secretShares = await sharing.getSecretShares();
    const { packets, commitments } = await sharing.createFeldmanPackets();
    secretShares.forEach(async (share: SecretShare) => {
      // Check verification
      const { value: secret, index } = share;
      const isValid = await verifyFeldmanCommitments(
        ctx,
        share,
        commitments,
      );
      expect(isValid).toBe(true);
      // Check parsing
      const packet = await parseFeldmanPacket(ctx, commitments, packets[index - 1]);
      expect(isEqualBuffer(packet.share.value, share.value)).toBe(true);
    });
  });

  it.each(systems)('failure over %s', async (system) => {
    const ctx = initBackend(system);
    const { secret, sharing } = await shareSecret(ctx, nrShares, threshold);
    const secretShares = await sharing.getSecretShares();
    const { packets, commitments } = await sharing.createFeldmanPackets();
    commitments[0] = await randomPublic(ctx);
    secretShares.forEach(async (share: SecretShare) => {
      // Check verification failure
      const verification = verifyFeldmanCommitments(
        ctx,
        share,
        commitments,
      );
      await expect(verification).rejects.toThrow('Invalid share');
      // Check parsing failure
      const parsed = parseFeldmanPacket(ctx, commitments, packets[share.index - 1]);
      await expect(parsed).rejects.toThrow('Invalid share');
    });
  });
})
