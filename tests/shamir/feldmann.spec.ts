import { initGroup } from '../../src/backend';
import { Point } from '../../src/backend/abstract';
import { SecretShare, ShamirSharing } from '../../src/shamir';
import { shareSecret, verifyFeldmannCommitments } from '../../src/shamir';
import { resolveTestConfig } from '../environ';

let { system, nrShares, threshold } = resolveTestConfig();


describe(`Secret share verification over ${system}`, () => {
  const ctx = initGroup(system);

  let sharing: ShamirSharing<Point>;
  let secretShares: SecretShare<Point>[];

  beforeAll(async () => {
    const secret = await ctx.randomScalar();
    sharing = await shareSecret(ctx, nrShares, threshold, secret);
    secretShares = await sharing.getSecretShares();
  })

  test('success', async () => {
    const { commitments } = await sharing.proveFeldmann();
    secretShares.forEach(async (share: SecretShare<Point>) => {
      const { value: secret, index } = share;
      const verified = await verifyFeldmannCommitments(
        ctx,
        share,
        commitments,
      );
      expect(verified).toBe(true);
    });
  });

  test('failure', async () => {
    const { commitments } = await sharing.proveFeldmann();
    const forgedCommitmnets = [
      ...commitments.slice(0, commitments.length - 1),
      (await ctx.randomPoint()).toBytes()
    ];
    secretShares.forEach(async (share: SecretShare<Point>) => {
      const verification = verifyFeldmannCommitments(
        ctx,
        share,
        forgedCommitmnets
      );
      await expect(verification).rejects.toThrow('Invalid share');
    });
  });
})
