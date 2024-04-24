import { backend } from '../../src';
import { Point } from '../../src/backend/abstract';
import { ScalarShare, PointShare } from '../../src/shamir';
import shamir from '../../src/shamir';

import { partialPermutations } from '../helpers';
import { resolveBackend } from '../environ';


describe('Reconstruction from shares', () => {
  const label = resolveBackend();
  const ctx = backend.initGroup(label);
  const nrShares = 5;
  const threshold = 3;

  let secret: bigint;
  let pub: Point;
  let secretShares: ScalarShare<Point>[];
  let publicShares: PointShare<Point>[];

  beforeAll(async () => {
    secret = await ctx.randomScalar();
    pub = await ctx.operate(secret, ctx.generator);
    const sharing = await shamir(ctx).distribute(secret, nrShares, threshold);
    secretShares = await sharing.getSecretShares();
    publicShares = await sharing.getPublicShares();
  })

  test(`Secret scalar reconstruction over ${label}`, async () => {
    partialPermutations(secretShares).forEach(async (qualifiedSet) => {
      let reconstructed = shamir(ctx).reconstructSecret(qualifiedSet);
      expect(reconstructed == secret).toBe(qualifiedSet.length >= threshold);
    });
  });

  test(`Public point reconstruction ${label}`, async () => {
    partialPermutations(publicShares).forEach(async (qualifiedSet) => {
      let reconstructed = await shamir(ctx).reconstructPublic(qualifiedSet);
      expect(await reconstructed.equals(pub)).toBe(qualifiedSet.length >= threshold);
    });
  });
})
