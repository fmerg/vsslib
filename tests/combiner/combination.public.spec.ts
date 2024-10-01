import { combinePublicShares } from 'vsslib/combiner';
import { partialPermutations, isEqualBuffer } from '../utils';
import { resolveTestConfig } from '../environ';
import { createRawSharing } from '../helpers';

let { systems, algorithms, nrShares, threshold } = resolveTestConfig();


describe('Combination of public shares (points)', () => {
  it.each(systems)('unconditioned - over %s', async (system) => {
    const { ctx, secret, publicBytes, publicShares } = await createRawSharing(system, nrShares, threshold);
    partialPermutations(publicShares).forEach(async (shares) => {
      let result = await combinePublicShares(ctx, shares);
      expect(isEqualBuffer(result, publicBytes)).toBe(shares.length >= threshold);
    });
  });
  it.each(systems)('threshold guard - over %s', async (system) => {
    const { ctx, secret, publicBytes, publicShares } = await createRawSharing(system, nrShares, threshold);
    partialPermutations(publicShares, 0, threshold - 1).forEach(async (shares) => {
      await expect(combinePublicShares(ctx, shares, threshold)).rejects.toThrow(
        'Insufficient number of shares'
      );
    });
    partialPermutations(publicShares, threshold, nrShares).forEach(async (shares) => {
      let result = await combinePublicShares(ctx, shares, threshold);
      expect(isEqualBuffer(result, publicBytes)).toBe(true);
    });
  });
});
