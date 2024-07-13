import { initBackend } from 'vsslib/backend';
import { randomPublic } from 'vsslib/secrets';
import { distributeSecret, SecretShare, ShamirSharing } from 'vsslib/dealer';
import { verifyFeldmanCommitments } from 'vsslib/shareholder';
import { resolveTestConfig } from '../environ';

let { systems, nrShares, threshold } = resolveTestConfig();


describe('Feldman VSS scheme', () => {
  it.each(systems)('success over %s', async (system) => {
    const ctx = initBackend(system);
    const { secret, sharing } = await distributeSecret(ctx, nrShares, threshold);
    const secretShares = await sharing.getSecretShares();
    const { commitments } = await sharing.createFeldmanPackets();
    secretShares.forEach(async (share: SecretShare) => {
      const { value: secret, index } = share;
      const isValid = await verifyFeldmanCommitments(
        ctx,
        share,
        commitments,
      );
      expect(isValid).toBe(true);
    });
  });

  it.each(systems)('failure over %s', async (system) => {
    const ctx = initBackend(system);
    const { secret, sharing } = await distributeSecret(ctx, nrShares, threshold);
    const secretShares = await sharing.getSecretShares();
    const { commitments } = await sharing.createFeldmanPackets();
    commitments[0] = await randomPublic(ctx);
    secretShares.forEach(async (share: SecretShare) => {
      const verification = verifyFeldmanCommitments(
        ctx,
        share,
        commitments,
      );
      await expect(verification).rejects.toThrow('Invalid share');
    });
  });
})
