import { initGroup } from '../../src/backend';
import { Point } from '../../src/backend/abstract';
import { SecretShare, ShamirSharing } from '../../src/shamir';
import { shareSecret } from '../../src/shamir';
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
    const pub = await ctx.randomPoint();
    const { commitments, bindings } = await sharing.provePedersen(pub);
    secretShares.forEach(async (share: SecretShare<Point>) => {
      const binding = bindings[share.index];
      const verified = await share.verifyPedersen(binding, pub, commitments);
      expect(verified).toBe(true);
    });
  });

  test('failure', async () => {
    const pub = await ctx.randomPoint();
    const { commitments, bindings } = await sharing.provePedersen(pub);
    secretShares.forEach(async (share: SecretShare<Point>) => {
      const forgedBinding = await ctx.randomScalar();
      const verified = await share.verifyPedersen(forgedBinding, pub, commitments);
      expect(verified).toBe(false);
    });
  });
})
