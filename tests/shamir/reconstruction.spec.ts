import { backend } from '../../src';
import { ScalarShare, PointShare } from '../../src/shamir';
import { Point } from '../../src/backend/abstract';
import { partialPermutations } from '../helpers';
import shamir from '../../src/shamir';


describe('Reconstruction from shares', () => {
  const label = 'ed25519';
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

  test('Secret scalar reconstruction', async () => {
    partialPermutations(secretShares).forEach(async (qualifiedSet) => {
      let reconstructed = shamir(ctx).reconstructSecret(qualifiedSet);
      expect(reconstructed == secret).toBe(qualifiedSet.length >= threshold);
    });
  });

  test('Public point reconstruction', async () => {
    partialPermutations(publicShares).forEach(async (qualifiedSet) => {
      let reconstructed = await shamir(ctx).reconstructPublic(qualifiedSet);
      expect(await reconstructed.equals(pub)).toBe(qualifiedSet.length >= threshold);
    });
  });
})
