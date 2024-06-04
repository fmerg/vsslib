import { initGroup } from '../../src/backend';
import { Group, Point } from '../../src/backend/abstract';
import {
  distributeSecret,
  reconstructSecret,
  reconstructPublic,
  SecretShare,
  PublicShare,
} from '../../src/shamir';

import { partialPermutations, isEqualBuffer } from '../utils';
import { resolveTestConfig } from '../environ';

let { system, nrShares, threshold } = resolveTestConfig();

function isEqualSecret<P extends Point>(ctx: Group<P>, a: Uint8Array, b: Uint8Array): boolean {
  return ctx.leBuff2Scalar(a) == ctx.leBuff2Scalar(b);
}

describe(`Reconstruction from shares over ${system}`, () => {
  const ctx = initGroup(system);

  let secret: Uint8Array;
  let pub: Point;
  let secretShares: SecretShare[];
  let publicShares: PublicShare[];

  beforeAll(async () => {
    secret = await ctx.randomSecret();
    pub = await ctx.exp(ctx.leBuff2Scalar(secret), ctx.generator);
    const sharing = await distributeSecret(ctx, nrShares, threshold, secret);
    secretShares = await sharing.getSecretShares();
    publicShares = await sharing.getPublicShares();
  })

  test('Secret reconstruction', async () => {
    partialPermutations(secretShares).forEach(async (qualifiedShares) => {
      let reconstructed = reconstructSecret(ctx, qualifiedShares);
      expect(isEqualSecret(ctx, reconstructed, secret)).toBe(qualifiedShares.length >= threshold);
    });
  });

  test('Public reconstruction', async () => {
    partialPermutations(publicShares).forEach(async (qualifiedShares) => {
      let reconstructed = await reconstructPublic(ctx, qualifiedShares);
      expect(isEqualBuffer(reconstructed, pub.toBytes())).toBe(qualifiedShares.length >= threshold);
    });
  });
})
