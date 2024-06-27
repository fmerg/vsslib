import { combinePublicShares } from '../../src/combiner';
import { partialPermutations, isEqualBuffer } from '../utils';
import { resolveTestConfig } from '../environ';
import { createSharingSetup } from '../helpers';

let { systems, algorithms, nrShares, threshold } = resolveTestConfig();


describe('Combination of public shares (points)', () => {
  it.each(systems)('unconditioned - over %s', async (system) => {
    const { ctx, secret, publicBytes, publicShares } = await createSharingSetup({
      system, nrShares, threshold
    });
    partialPermutations(publicShares).forEach(async (qualifiedShares) => {
      let result = await combinePublicShares(ctx, qualifiedShares);
      expect(isEqualBuffer(result, publicBytes)).toBe(qualifiedShares.length >= threshold);
    });
  });
  it.each(systems)('threshold guard - over %s', async (system) => {
    const { ctx, secret, publicBytes, publicShares } = await createSharingSetup({
      system, nrShares, threshold
    });
    partialPermutations(publicShares, 0, threshold - 1).forEach(async (qualifiedShares) => {
      await expect(combinePublicShares(ctx, qualifiedShares, threshold)).rejects.toThrow(
        'Insufficient number of shares'
      );
    });
    partialPermutations(publicShares, threshold, nrShares).forEach(async (qualifiedShares) => {
      let result = await combinePublicShares(ctx, qualifiedShares, threshold);
      expect(isEqualBuffer(result, publicBytes)).toBe(true);
    });
  });
});
