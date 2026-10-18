import { combinePublicShares } from 'vsslib/combiner';
import { partialPermutations, isEqualBuffer } from '../utils';
import { resolveTestConfig } from '../environ';
import { createRawSharing } from '../helpers';

let { systems, algorithms, nrShares, threshold } = resolveTestConfig();


describe('Combination of public shares (points)', () => {
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
  it.each(systems)('threshold validation - over %s', async (system) => {
    const { ctx, publicShares } = await createRawSharing(system, nrShares, threshold);
    for (const bad of [0, -1, 1.5, undefined]) {
      await expect(combinePublicShares(ctx, publicShares, bad as unknown as number)).rejects.toThrow(
        'Threshold must be a positive integer'
      );
    }
  });
});
