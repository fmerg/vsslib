import { combineSecretShares, isEqualSecret } from 'vsslib';
import { partialPermutations } from '../utils';
import { resolveTestConfig } from '../environ';
import { createRawSharing } from '../helpers';

let { systems, algorithms, nrShares, threshold } = resolveTestConfig();

describe('Combination of secret shares (scalars)', () => {
  it.each(systems)('threshold guard - over %s', async (system) => {
    const { ctx, secret, secretShares } = await createRawSharing(system, nrShares, threshold);
    partialPermutations(secretShares, 0, threshold - 1).forEach(async (shares) => {
      await expect(combineSecretShares(ctx, shares, threshold)).rejects.toThrow(
        'Insufficient number of shares'
      );
    });
    partialPermutations(secretShares, threshold, nrShares).forEach(async (shares) => {
      let result = await combineSecretShares(ctx, shares, threshold);
      expect(await isEqualSecret(ctx, result, secret)).toBe(true);
    });
  });
  it.each(systems)('threshold validation - over %s', async (system) => {
    const { ctx, secretShares } = await createRawSharing(system, nrShares, threshold);
    for (const bad of [0, -1, 1.5, undefined]) {
      await expect(combineSecretShares(ctx, secretShares, bad as unknown as number)).rejects.toThrow(
        'Threshold must be a positive integer'
      );
    }
  });
});
