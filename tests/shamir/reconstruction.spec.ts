import { initGroup } from '../../src/backend';
import { Point } from '../../src/backend/abstract';
import {
  shareSecret,
  reconstructSecret,
  reconstructPublic,
  SecretShare,
  PubShare,
} from '../../src/shamir';

import { partialPermutations } from '../helpers';
import { resolveBackend, resolveThresholdParams } from '../environ';


const label = resolveBackend();
const { nrShares, threshold } = resolveThresholdParams();

describe(`Reconstruction from shares over ${label}`, () => {
  const ctx = initGroup(label);

  let secret: bigint;
  let pub: Point;
  let secretShares: SecretShare<Point>[];
  let publicShares: PubShare<Point>[];

  beforeAll(async () => {
    secret = await ctx.randomScalar();
    pub = await ctx.operate(secret, ctx.generator);
    const sharing = await shareSecret(ctx, nrShares, threshold, secret);
    secretShares = await sharing.getSecretShares();
    publicShares = await sharing.getPublicShares();
  })

  test('Secret scalar reconstruction', async () => {
    partialPermutations(secretShares).forEach(async (qualifiedShares) => {
      let reconstructed = reconstructSecret(ctx, qualifiedShares);
      expect(reconstructed == secret).toBe(qualifiedShares.length >= threshold);
    });
  });

  test('Public point reconstruction', async () => {
    partialPermutations(publicShares).forEach(async (qualifiedShares) => {
      let reconstructed = await reconstructPublic(ctx, qualifiedShares);
      expect(await reconstructed.equals(pub)).toBe(qualifiedShares.length >= threshold);
    });
  });
})
