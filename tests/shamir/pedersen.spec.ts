import { initGroup } from '../../src/backend';
import { Point } from '../../src/backend/abstract';
import { SecretShare, ShamirSharing } from '../../src/shamir';
import { shareSecret, verifyPedersenCommitments } from '../../src/shamir';
import { resolveTestConfig } from '../environ';
import { leInt2Buff } from '../../src/arith';

let { system, nrShares, threshold } = resolveTestConfig();


describe(`Secret share verification over ${system}`, () => {
  const ctx = initGroup(system);

  let sharing: ShamirSharing<Point>;
  let secretShares: SecretShare[];

  beforeAll(async () => {
    const secret = await ctx.randomScalar();
    sharing = await shareSecret(ctx, nrShares, threshold, secret);
    secretShares = await sharing.getSecretShares();
  })

  test('success', async () => {
    const publicBytes = (await ctx.randomPoint()).toBytes();
    const { commitments, bindings } = await sharing.createPedersenPackets(publicBytes);
    secretShares.forEach(async (share: SecretShare) => {
      const binding = bindings[share.index - 1];
      const verified = await verifyPedersenCommitments(
        ctx,
        share,
        binding,
        publicBytes,
        commitments
      );
      expect(verified).toBe(true);
    });
  });

  test('failure', async () => {
    const publicBytes = (await ctx.randomPoint()).toBytes();
    const { commitments, bindings } = await sharing.createPedersenPackets(publicBytes);
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
