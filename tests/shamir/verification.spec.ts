import { backend } from '../../src';
import { Point } from '../../src/backend/abstract';
import { SecretShare, SecretSharing } from '../../src/shamir';
import { shareSecret, verifyFeldmann, verifyPedersen } from '../../src/shamir';
import { resolveTestConfig } from '../environ';

let { label, nrShares, threshold } = resolveTestConfig();


describe(`Secret share verification over ${label}`, () => {
  const ctx = backend.initGroup(label);

  let sharing: SecretSharing<Point>;
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
      const verified = await verifyFeldmann(ctx, share, commitments);
      expect(verified).toBe(true);
    });
  });

  test('Feldmann - failure', async () => {
    const { commitments } = await sharing.proveFeldmann();
    const forgedCommitmnets = [...commitments.slice(0, commitments.length - 1), await ctx.randomPoint()];
    secretShares.forEach(async (share: SecretShare<Point>) => {
      const verified = await verifyFeldmann(ctx, share, forgedCommitmnets);
      expect(verified).toBe(false);
    });
  });

  test('Pedersen - success', async () => {
    const hPub = await ctx.randomPoint();
    const { bindings, commitments } = await sharing.provePedersen(hPub);
    secretShares.forEach(async (share: SecretShare<Point>) => {
      const binding = bindings[share.index];
      const verified = await verifyPedersen(ctx, share, binding, hPub, commitments);
      expect(verified).toBe(true);
    });
  });

  test('Pedersen - failure', async () => {
    const hPub = await ctx.randomPoint();
    const { bindings, commitments } = await sharing.provePedersen(hPub);
    secretShares.forEach(async (share: SecretShare<Point>) => {
      const forgedBinding = await ctx.randomScalar();
      const verified = await verifyPedersen(ctx, share, forgedBinding, hPub, commitments);
      expect(verified).toBe(false);
    });
  });
})
