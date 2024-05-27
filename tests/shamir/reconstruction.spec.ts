import { initGroup } from '../../src/backend';
import { Point } from '../../src/backend/abstract';
import {
  shareSecret,
  reconstructSecret,
  reconstructPoint,
  SecretShare,
  PointShare,
} from '../../src/shamir';

import { partialPermutations } from '../helpers';
import { resolveTestConfig } from '../environ';

let { system, nrShares, threshold } = resolveTestConfig();

describe(`Reconstruction from shares over ${system}`, () => {
  const ctx = initGroup(system);

  let secret: bigint;
  let pub: Point;
  let secretShares: SecretShare<Point>[];
  let publicShares: PointShare<Point>[];

  beforeAll(async () => {
    secret = await ctx.randomScalar();
    pub = await ctx.exp(secret, ctx.generator);
    const sharing = await shareSecret(ctx, nrShares, threshold, secret);
    secretShares = await sharing.getSecretShares();
    publicShares = await sharing.getPointShares();
  })

  test('Secret reconstruction', async () => {
    partialPermutations(secretShares).forEach(async (qualifiedShares) => {
      let reconstructed = reconstructSecret(ctx, qualifiedShares);
      expect(reconstructed == secret).toBe(qualifiedShares.length >= threshold);
    });
  });

  test('Point reconstruction', async () => {
    partialPermutations(publicShares).forEach(async (qualifiedShares) => {
      let reconstructed = await reconstructPoint(ctx, qualifiedShares);
      expect(await reconstructed.equals(pub)).toBe(qualifiedShares.length >= threshold);
    });
  });
})
