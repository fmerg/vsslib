import { backend } from '../../src';
import { Point } from '../../src/backend/abstract';
import { SecretShare, SecretSharing } from '../../src/shamir';

import shamir from '../../src/shamir';

import { resolveBackend } from '../environ';

const label = resolveBackend();
const nrShares = 5;
const threshold = 3;

describe(`Secret share verification over ${label}`, () => {
  const ctx = backend.initGroup(label);

  let sharing: SecretSharing<Point>;
  let secretShares: SecretShare<Point>[];

  beforeAll(async () => {
    const secret = await ctx.randomScalar();
    sharing = await shamir(ctx).shareSecret(nrShares, threshold, secret);
    secretShares = await sharing.getSecretShares();
  })

  test('Feldmann VSS scheme - success', async () => {
    const { commitments } = await sharing.proveFeldmann();
    secretShares.forEach(async (share: SecretShare<Point>) => {
      const { value: secret, index } = share;
      const verified = await shamir(ctx).verifyFeldmann(share, commitments);
      expect(verified).toBe(true);
    });
  });

  test('Feldmann VSS scheme - failure', async () => {
    const { commitments } = await sharing.proveFeldmann();
    const forgedCommitmnets = [...commitments.slice(0, commitments.length - 1), await ctx.randomPoint()];
    secretShares.forEach(async (share: SecretShare<Point>) => {
      const verified = await shamir(ctx).verifyFeldmann(share, forgedCommitmnets);
      expect(verified).toBe(false);
    });
  });

  test('Pedersen VSS scheme - success', async () => {
    const hPub = await ctx.randomPoint();
    const { bindings, commitments } = await sharing.provePedersen(hPub);
    secretShares.forEach(async (share: SecretShare<Point>) => {
      const binding = bindings[share.index];
      const verified = await shamir(ctx).verifyPedersen(share, binding, hPub, commitments);
      expect(verified).toBe(true);
    });
  });

  test('Pedersen VSS scheme - failure', async () => {
    const hPub = await ctx.randomPoint();
    const { bindings, commitments } = await sharing.provePedersen(hPub);
    secretShares.forEach(async (share: SecretShare<Point>) => {
      const forgedBinding = await ctx.randomScalar();
      const verified = await shamir(ctx).verifyPedersen(share, forgedBinding, hPub, commitments);
      expect(verified).toBe(false);
    });
  });
})
