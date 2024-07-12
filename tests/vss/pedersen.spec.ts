import { initBackend } from 'vsslib/backend';
import { Point } from 'vsslib/backend';
import { distributeSecret, SecretShare, ShamirSharing } from 'vsslib/dealer';
import { verifyPedersenCommitments } from 'vsslib/shareholder';
import { resolveTestConfig } from '../environ';
import { leInt2Buff } from 'vsslib/arith';

let { systems, nrShares, threshold } = resolveTestConfig();


describe('Pedersen VSS scheme', () => {
  it.each(systems)('success over %s', async (system) => {
    const ctx = initBackend(system);
    const { secret, sharing } = await distributeSecret(ctx, nrShares, threshold);
    const publicBytes = await ctx.randomPublic();
    const { commitments, bindings } = await sharing.createPedersenPackets(publicBytes);
    const secretShares = await sharing.getSecretShares();
    secretShares.forEach(async (share: SecretShare) => {
      const binding = bindings[share.index - 1];
      const isValid = await verifyPedersenCommitments(
        ctx,
        share,
        binding,
        publicBytes,
        commitments
      );
      expect(isValid).toBe(true);
    });
  });
  it.each(systems)('failure over %s', async (system) => {
    const ctx = initBackend(system);
    const { secret, sharing } = await distributeSecret(ctx, nrShares, threshold);
    const publicBytes = await ctx.randomPublic();
    const { commitments, bindings } = await sharing.createPedersenPackets(publicBytes);
    const secretShares = await sharing.getSecretShares();
    secretShares.forEach(async (share: SecretShare) => {
      const forgedBinding = leInt2Buff(await ctx.randomScalar());
      const verification = verifyPedersenCommitments(
        ctx,
        share,
        forgedBinding,
        publicBytes,
        commitments
      );
      await expect(verification).rejects.toThrow('Invalid share');
    });
  });
})
