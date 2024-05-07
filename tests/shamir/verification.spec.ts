import { initGroup } from '../../src/backend';
import { Point } from '../../src/backend/abstract';
import { SecretShare, SecretSharing } from '../../src/shamir';
import { shareSecret, verifyFeldmann, verifyPedersen } from '../../src/shamir';
import { resolveTestConfig } from '../environ';

let { system, nrShares, threshold } = resolveTestConfig();


describe(`Secret share verification over ${system}`, () => {
  const ctx = initGroup(system);

  let sharing: SecretSharing<Point>;
  let secretShares: SecretShare[];

  beforeAll(async () => {
    const secret = await ctx.randomScalar();
    sharing = await shareSecret(ctx, nrShares, threshold, secret);
    secretShares = await sharing.getSecretShares();
  })

  test('Feldmann - success', async () => {
    const { commitments } = await sharing.proveFeldmann();
    secretShares.forEach(async (share: SecretShare) => {
      const { value: secret, index } = share;
      const verified = await verifyFeldmann(ctx, share, commitments);
      expect(verified).toBe(true);
    });
  });

  test('Feldmann - failure', async () => {
    const { commitments } = await sharing.proveFeldmann();
    const forgedCommitmnets = [...commitments.slice(0, commitments.length - 1), await ctx.randomPoint()];
    secretShares.forEach(async (share: SecretShare) => {
      const verified = await verifyFeldmann(ctx, share, forgedCommitmnets);
      expect(verified).toBe(false);
    });
  });

  test('Pedersen - success', async () => {
    const pub = await ctx.randomPoint();
    const { commitments, bindings } = await sharing.provePedersen(pub);
    secretShares.forEach(async (share: SecretShare) => {
      const binding = bindings[share.index];
      const verified = await verifyPedersen(ctx, share, binding, pub, commitments);
      expect(verified).toBe(true);
    });
  });

  test('Pedersen - failure', async () => {
    const pub = await ctx.randomPoint();
    const { commitments, bindings } = await sharing.provePedersen(pub);
    secretShares.forEach(async (share: SecretShare) => {
      const forgedBinding = await ctx.randomScalar();
      const verified = await verifyPedersen(ctx, share, forgedBinding, pub, commitments);
      expect(verified).toBe(false);
    });
  });
})
