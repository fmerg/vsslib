import { recoverKey } from '../../src/combiner';
import { SecretSharePacket } from '../../src/shamir';
import { cartesian, partialPermutations } from '../utils';
import { resolveTestConfig } from '../environ';
import { isEqualSecret, createSharingSetup } from '../helpers';

const { systems, algorithms, nrShares, threshold } = resolveTestConfig();


describe('Private key recovery - unconditioned', () => {
  it.each(systems)('over %s', async (system) => {
    const { ctx, secret, secretShares } = await createSharingSetup({
      system, nrShares, threshold
    });

    partialPermutations(secretShares).forEach(async (qualifiedShares) => {
      let result = await recoverKey(ctx, qualifiedShares);
      expect(isEqualSecret(ctx, result.bytes, secret)).toBe(qualifiedShares.length >= threshold);
    });
  });
});

describe('Private key recovery - threshold guard', () => {
  it.each(systems)('over %s', async (system) => {
    const { ctx, secret, secretShares } = await createSharingSetup({
      system, nrShares, threshold
    });

    partialPermutations(secretShares, 0, threshold - 1).forEach(async (qualifiedShares) => {
      await expect(recoverKey(ctx, qualifiedShares, threshold)).rejects.toThrow(
        'Insufficient number of shares'
      );
    });
    partialPermutations(secretShares, threshold, nrShares).forEach(async (qualifiedShares) => {
      let result = await recoverKey(ctx, qualifiedShares, threshold);
      expect(isEqualSecret(ctx, result.bytes, secret)).toBe(true);
    });
  });
});
