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

  test('Feldmann - success', async () => {
    const { commitments } = await sharing.proveFeldmann();
    secretShares.forEach(async (share: SecretShare<Point>) => {
      const { value: secret, index } = share;
      const verified = await share.verifyFeldmann(commitments);
      expect(verified).toBe(true);
    });
  });

  test('Feldmann - failure', async () => {
    const { commitments } = await sharing.proveFeldmann();
    const forgedCommitmnets = [...commitments.slice(0, commitments.length - 1), await ctx.randomPoint()];
    secretShares.forEach(async (share: SecretShare<Point>) => {
      const verified = await share.verifyFeldmann(forgedCommitmnets);
      expect(verified).toBe(false);
    });
  });

  test('Pedersen - success', async () => {
    const pub = await ctx.randomPoint();
    const { commitments, bindings } = await sharing.provePedersen(pub);
    secretShares.forEach(async (share: SecretShare<Point>) => {
      const binding = bindings[share.index];
      const verified = await share.verifyPedersen(binding, pub, commitments);
      expect(verified).toBe(true);
    });
  });

  test('Pedersen - failure', async () => {
    const pub = await ctx.randomPoint();
    const { commitments, bindings } = await sharing.provePedersen(pub);
    secretShares.forEach(async (share: SecretShare<Point>) => {
      const forgedBinding = await ctx.randomScalar();
      const verified = await share.verifyPedersen(forgedBinding, pub, commitments);
      expect(verified).toBe(false);
    });
  });
})
