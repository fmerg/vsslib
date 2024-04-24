import { backend } from '../../src';
import { Point } from '../../src/backend/abstract';
import { SecretShare, PubShare } from '../../src/shamir';

import shamir from '../../src/shamir';

import { partialPermutations } from '../helpers';
import { resolveBackend } from '../environ';


const label = resolveBackend();
const nrShares = 5;
const threshold = 3;

describe(`Reconstruction from shares over ${label}`, () => {
  const ctx = backend.initGroup(label);

  let secret: bigint;
  let pub: Point;
  let secretShares: SecretShare<Point>[];
  let publicShares: PubShare<Point>[];

  beforeAll(async () => {
    secret = await ctx.randomScalar();
    pub = await ctx.operate(secret, ctx.generator);
    const sharing = await shamir(ctx).shareSecret(nrShares, threshold, secret);
    secretShares = await sharing.getSecretShares();
    publicShares = await sharing.getPublicShares();
  })

  test('Secret scalar reconstruction', async () => {
    partialPermutations(secretShares).forEach(async (qualifiedShares) => {
      let reconstructed = shamir(ctx).reconstructSecret(qualifiedShares);
      expect(reconstructed == secret).toBe(qualifiedShares.length >= threshold);
    });
  });

  test('Public point reconstruction', async () => {
    partialPermutations(publicShares).forEach(async (qualifiedShares) => {
      let reconstructed = await shamir(ctx).reconstructPublic(qualifiedShares);
      expect(await reconstructed.equals(pub)).toBe(qualifiedShares.length >= threshold);
    });
  });
})
