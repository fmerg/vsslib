import { initGroup } from '../../src/backend';
import { Group, Point } from '../../src/backend/abstract';
import { distributeSecret, recoverSecret, recoverPublic } from '../../src/shamir';

import { partialPermutations, isEqualBuffer } from '../utils';
import { resolveTestConfig } from '../environ';

let { systems, nrShares, threshold } = resolveTestConfig();

function isEqualSecret<P extends Point>(ctx: Group<P>, a: Uint8Array, b: Uint8Array): boolean {
  return ctx.leBuff2Scalar(a) == ctx.leBuff2Scalar(b);
}

describe('Secret recovery', () => {
  it.each(systems)('success over %s', async (system) => {
    const ctx = initGroup(system);
    const secret = await ctx.randomSecret();
    const pub = await ctx.exp(ctx.generator, ctx.leBuff2Scalar(secret));
    const sharing = await distributeSecret(ctx, nrShares, threshold, secret);
    const secretShares = await sharing.getSecretShares();
    partialPermutations(secretShares).forEach(async (qualifiedShares) => {
      let recovered = recoverSecret(ctx, qualifiedShares);
      expect(isEqualSecret(ctx, recovered, secret)).toBe(qualifiedShares.length >= threshold);
    });
  });
});

describe('Public recovery', () => {
  it.each(systems)('success over %s', async (system) => {
    const ctx = initGroup(system);
    const secret = await ctx.randomSecret();
    const pub = await ctx.exp(ctx.generator, ctx.leBuff2Scalar(secret));
    const sharing = await distributeSecret(ctx, nrShares, threshold, secret);
    const publicShares = await sharing.getPublicShares();
    partialPermutations(publicShares).forEach(async (qualifiedShares) => {
      let recovered = await recoverPublic(ctx, qualifiedShares);
      expect(isEqualBuffer(recovered, pub.toBytes())).toBe(qualifiedShares.length >= threshold);
    });
  });
});
