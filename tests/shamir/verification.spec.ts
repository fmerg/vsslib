import { shamir, backend } from '../../src';
import { ScalarShare, PointShare, ScalarSharing } from '../../src/shamir';
import { Point } from '../../src/backend/abstract';


describe('Secret share verification', () => {
  const label = 'ed25519';
  const ctx = backend.initGroup(label);
  const nrShares = 5;
  const threshold = 3;

  let sharing: ScalarSharing<Point>;
  let secretShares: ScalarShare<Point>[];

  beforeAll(async () => {
    const secret = await ctx.randomScalar();
    sharing = await shamir.distribute(ctx, secret, nrShares, threshold);
    secretShares = await sharing.getSecretShares();
  })

  test('Feldmann VSS scheme - success', async () => {
    const { commitments } = await sharing.getFeldmann();
    secretShares.forEach(async (share: ScalarShare<Point>) => {
      const verified = await shamir.verifySecretShare(ctx, share, commitments);
      expect(verified).toBe(true);
    });
  });

  test('Feldmann VSS scheme - failure', async () => {
    const { commitments } = await sharing.getFeldmann();
    const forgedCommitmnets = [...commitments.slice(0, commitments.length - 1), await ctx.randomPoint()];[]
    secretShares.forEach(async (share: ScalarShare<Point>) => {
      const verified = await shamir.verifySecretShare(ctx, share, forgedCommitmnets);
      expect(verified).toBe(false);
    });
  });

  test('Pedersen VSS scheme - success', async () => {
    const hPub = await ctx.randomPoint();
    const { bindings, commitments } = await sharing.getPedersen(hPub);
    secretShares.forEach(async (share: ScalarShare<Point>) => {
      const binding = bindings[share.index];
      const verified = await shamir.verifySecretShare(ctx, share, commitments, { binding, hPub });
      expect(verified).toBe(true);
    });
  });

  test('Pedersen VSS scheme - failure', async () => {
    const hPub = await ctx.randomPoint();
    const { bindings, commitments } = await sharing.getPedersen(hPub);
    secretShares.forEach(async (share: ScalarShare<Point>) => {
      const forged = await ctx.randomScalar();
      const verified = await shamir.verifySecretShare(ctx, share, commitments, { binding: forged, hPub });
      expect(verified).toBe(false);
    });
  });
})
