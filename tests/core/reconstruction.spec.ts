import { reconstructKey, reconstructPublic } from '../../src/core';

import { partialPermutations } from '../helpers';
import { resolveTestConfig } from '../environ';
import { createKeyDistributionSetup } from './helpers';

const { label, nrShares, threshold } = resolveTestConfig();


describe(`Key reconstruction over ${label}`, () => {
  let setup: any;

  beforeAll(async () => {
    setup = await createKeyDistributionSetup({ label, nrShares, threshold });
  });

  test('Private reconstruction - skip threshold check', async () => {
    const { privateKey, privateShares, ctx } = setup;
    partialPermutations(privateShares).forEach(async (qualifiedShares) => {
      const reconstructed = await reconstructKey(ctx, qualifiedShares);
      expect(await reconstructed.equals(privateKey)).toBe(
        qualifiedShares.length >= threshold
      );
    });
  });
  test('Private reconstruction - with threshold check', async () => {
    const { privateKey, privateShares, ctx } = setup;
    partialPermutations(privateShares, 0, threshold - 1).forEach(async (qualifiedShares) => {
      await expect(reconstructKey(ctx, qualifiedShares, threshold)).rejects.toThrow(
        'Insufficient number of shares'
      );
    });
    partialPermutations(privateShares, threshold, nrShares).forEach(async (qualifiedShares) => {
      const reconstructed = await reconstructKey(ctx, qualifiedShares, threshold);
      expect(await reconstructed.equals(privateKey)).toBe(true);
    });
  });
  test('Public reconstruction - skip threshold check', async () => {
    const { publicKey, publicShares, ctx } = setup;
    partialPermutations(publicShares).forEach(async (qualifiedShares) => {
      const reconstructed = await reconstructPublic(ctx, qualifiedShares);
      expect(await reconstructed.equals(publicKey)).toBe(
        qualifiedShares.length >= threshold
      );
    });
  });
  test('Public reconstruction - with threshold check', async () => {
    const { publicKey, publicShares, ctx } = setup;
    partialPermutations(publicShares, 0, threshold - 1).forEach(async (qualifiedShares) => {
      await expect(reconstructPublic(ctx, qualifiedShares, threshold)).rejects.toThrow(
        'Insufficient number of shares'
      );
    });
    partialPermutations(publicShares, threshold, nrShares).forEach(async (qualifiedShares) => {
      const reconstructed = await reconstructPublic(ctx, qualifiedShares, threshold);
      expect(await reconstructed.equals(publicKey)).toBe(true);
    });
  });
});
