import { combineSecretShares, isEqualSecret } from '../../src';
import { partialPermutations } from '../utils';
import { resolveTestConfig } from '../environ';
import { createSharingSetup } from '../helpers';

let { systems, algorithms, nrShares, threshold } = resolveTestConfig();

describe('Combination of secret shares (scalars)', () => {
  it.each(systems)('unconditioned - over %s', async (system) => {
    const { ctx, secret, secretShares } = await createSharingSetup({
      system, nrShares, threshold
    });
    partialPermutations(secretShares).forEach(async (qualifiedShares) => {
      let result = await combineSecretShares(ctx, qualifiedShares);
      expect(await isEqualSecret(ctx, result, secret)).toBe(qualifiedShares.length >= threshold);
    });
  });
  it.each(systems)('threshold guard - over %s', async (system) => {
    const { ctx, secret, secretShares } = await createSharingSetup({
      system, nrShares, threshold
    });

    partialPermutations(secretShares, 0, threshold - 1).forEach(async (qualifiedShares) => {
      await expect(combineSecretShares(ctx, qualifiedShares, threshold)).rejects.toThrow(
        'Insufficient number of shares'
      );
    });
    partialPermutations(secretShares, threshold, nrShares).forEach(async (qualifiedShares) => {
      let result = await combineSecretShares(ctx, qualifiedShares, threshold);
      expect(await isEqualSecret(ctx, result, secret)).toBe(true);
    });
  });
});
