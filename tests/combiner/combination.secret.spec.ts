import { combineSecretShares, isEqualSecret } from 'vsslib';
import { partialPermutations, isEqualBuffer } from '../utils';
import { resolveTestConfig } from '../environ';
import { createRawSharing } from '../helpers';

let { systems, algorithms, nrShares, threshold } = resolveTestConfig();

describe('Combination of secret shares (scalars)', () => {
  it.each(systems)('unconditioned - over %s', async (system) => {
    const { ctx, secret, secretShares } = await createRawSharing(system, nrShares, threshold);
    partialPermutations(secretShares).forEach(async (shares) => {
      // Combining no shares yields zero, which is not a valid secret, so
      // compare encodings
      let result = await combineSecretShares(ctx, shares);
      expect(isEqualBuffer(result, secret)).toBe(shares.length >= threshold);
    });
  });
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
});
