import { initBackend } from '../../src/backend';
import { Point } from '../../src/backend/abstract';
import { SecretShare, ShamirSharing } from '../../src/dealer';
import { distributeSecret, verifyFeldmanCommitments } from '../../src/dealer';
import { resolveTestConfig } from '../environ';

let { systems, nrShares, threshold } = resolveTestConfig();


describe('Feldman VSS scheme', () => {
  it.each(systems)('success over %s', async (system) => {
    const ctx = initBackend(system);
    const secret = await ctx.randomSecret();
    const { sharing } = await distributeSecret(ctx, nrShares, threshold, secret);
    const secretShares = await sharing.getSecretShares();
    const { commitments } = await sharing.createFeldmanPackets();
    secretShares.forEach(async (share: SecretShare) => {
      const { value: secret, index } = share;
      const verified = await verifyFeldmanCommitments(
        ctx,
        share,
        commitments,
      );
      expect(verified).toBe(true);
    });
  });

  it.each(systems)('failure over %s', async (system) => {
    const ctx = initBackend(system);
    const secret = await ctx.randomSecret();
    const { sharing } = await distributeSecret(ctx, nrShares, threshold, secret);
    const secretShares = await sharing.getSecretShares();
    const { commitments } = await sharing.createFeldmanPackets();
    const forgedCommitmnets = [
      ...commitments.slice(0, commitments.length - 1),
      await ctx.randomPublic()
    ];
    secretShares.forEach(async (share: SecretShare) => {
      const verification = verifyFeldmanCommitments(
        ctx,
        share,
        forgedCommitmnets
      );
      await expect(verification).rejects.toThrow('Invalid share');
    });
  });
})
