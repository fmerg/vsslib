import { shamir, backend } from '../../src';
import { SecretShare, PointShare, Distribution } from '../../src/shamir/common';
import { Point } from '../../src/backend/abstract';


describe('Secret share verification', () => {
  const label = 'ed25519';
  const ctx = backend.initGroup(label);
  const nrShares = 5;
  const threshold = 3;

  let distribution: Distribution<Point>;
  let secretShares: SecretShare<Point>[];

  beforeAll(async () => {
    const secret = await ctx.randomScalar();
    distribution = await shamir.shareSecret(ctx, secret, nrShares, threshold);
    secretShares = await distribution.getSecretShares();
  })

  test('Feldmann VSS scheme - success', async () => {
    const { commitments } = await distribution.getFeldmannCommitments();
    secretShares.forEach(async (share: SecretShare<Point>) => {
      const verified = await shamir.verifySecretShare(ctx, share, commitments);
      expect(verified).toBe(true);
    });
  });

  test('Feldmann VSS scheme - failure', async () => {
    const { commitments } = await distribution.getFeldmannCommitments();
    const forgedCommitmnets = [...commitments.slice(0, commitments.length - 1), await ctx.randomPoint()];[]
    secretShares.forEach(async (share: SecretShare<Point>) => {
      const verified = await shamir.verifySecretShare(ctx, share, forgedCommitmnets);
      expect(verified).toBe(false);
    });
  });

  test('Pedersen VSS scheme - success', async () => {
    const hPub = await ctx.randomPoint();
    const { bindings, commitments } = await distribution.getPedersenCommitments(hPub);
    secretShares.forEach(async (share: SecretShare<Point>) => {
      const binding = bindings[share.index];
      const verified = await shamir.verifySecretShare(ctx, share, commitments, { binding, hPub });
      expect(verified).toBe(true);
    });
  });

  test('Pedersen VSS scheme - failure', async () => {
    const hPub = await ctx.randomPoint();
    const { bindings, commitments } = await distribution.getPedersenCommitments(hPub);
    secretShares.forEach(async (share: SecretShare<Point>) => {
      const forged = await ctx.randomScalar();
      const verified = await shamir.verifySecretShare(ctx, share, commitments, { binding: forged, hPub });
      expect(verified).toBe(false);
    });
  });
})
