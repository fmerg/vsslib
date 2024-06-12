import { recoverSecret, combinePublics } from '../../src/shamir';
import { cartesian, partialPermutations, isEqualBuffer } from '../utils';
import { resolveTestConfig } from '../environ';
import { randomDlogPair, isEqualSecret, createSharingSetup } from '../helpers';

let { systems, algorithms, nrShares, threshold } = resolveTestConfig();

describe('Secret recovery - unconditioned', () => {
  it.each(systems)('over %s', async (system) => {
    const { ctx, secret, secretShares } = await createSharingSetup({
      system, nrShares, threshold
    });

    partialPermutations(secretShares).forEach(async (qualifiedShares) => {
      let result = await recoverSecret(ctx, qualifiedShares);
      expect(isEqualSecret(ctx, result, secret)).toBe(qualifiedShares.length >= threshold);
    });
  });
});

describe('Secret recovery - threshold guard', () => {
  it.each(systems)('over %s', async (system) => {
    const { ctx, secret, secretShares } = await createSharingSetup({
      system, nrShares, threshold
    });

    partialPermutations(secretShares, 0, threshold - 1).forEach(async (qualifiedShares) => {
      await expect(recoverSecret(ctx, qualifiedShares, threshold)).rejects.toThrow(
        'Insufficient number of shares'
      );
    });
    partialPermutations(secretShares, threshold, nrShares).forEach(async (qualifiedShares) => {
      let result = await recoverSecret(ctx, qualifiedShares, threshold);
      expect(isEqualSecret(ctx, result, secret)).toBe(true);
    });
  });
});

describe('Public shares combination - unconditioned', () => {
  it.each(systems)('over %s', async (system) => {
    const { ctx, secret, publicBytes, publicShares } = await createSharingSetup({
      system, nrShares, threshold
    });

    partialPermutations(publicShares).forEach(async (qualifiedShares) => {
      let result = await combinePublics(ctx, qualifiedShares);
      expect(isEqualBuffer(result, publicBytes)).toBe(qualifiedShares.length >= threshold);
    });
  });
});

describe('Public shares combnation - threshold guard', () => {
  it.each(systems)('over %s', async (system) => {
    const { ctx, secret, publicBytes, publicShares } = await createSharingSetup({
      system, nrShares, threshold
    });

    partialPermutations(publicShares, 0, threshold - 1).forEach(async (qualifiedShares) => {
      await expect(combinePublics(ctx, qualifiedShares, threshold)).rejects.toThrow(
        'Insufficient number of shares'
      );
    });
    partialPermutations(publicShares, threshold, nrShares).forEach(async (qualifiedShares) => {
      let result = await combinePublics(ctx, qualifiedShares, threshold);
      expect(isEqualBuffer(result, publicBytes)).toBe(true);
    });
  });
});
