import { partialPermutations } from '../helpers';
import { resolveBackend, resolveThresholdParams } from '../environ';
import { createKeyDistributionSetup } from './helpers';
import { VssParty } from '../../src/core';


const label = resolveBackend();
const { nrShares, threshold } = resolveThresholdParams();


describe(`Key reconstruction over ${label}`, () => {
  let setup: any;

  beforeAll(async () => {
    setup = await createKeyDistributionSetup({ label, nrShares, threshold });
  });

  test('Private reconstruction - skip threshold check', async () => {
    const { privateKey, privateShares, vss } = setup;
    partialPermutations(privateShares).forEach(async (qualifiedShares) => {
      const reconstructed = await vss.reconstructKey(qualifiedShares);
      expect(await reconstructed.equals(privateKey)).toBe(
        qualifiedShares.length >= threshold
      );
    });
  });
  test('Private reconstruction - with threshold check', async () => {
    const { privateKey, privateShares, vss } = setup;
    partialPermutations(privateShares, 0, threshold - 1).forEach(async (qualifiedShares) => {
      await expect(vss.reconstructKey(qualifiedShares, threshold)).rejects.toThrow(
        'Insufficient number of shares'
      );
    });
    partialPermutations(privateShares, threshold, nrShares).forEach(async (qualifiedShares) => {
      const reconstructed = await vss.reconstructKey(qualifiedShares, threshold);
      expect(await reconstructed.equals(privateKey)).toBe(true);
    });
  });
  test('Public reconstruction - skip threshold check', async () => {
    const { publicKey, publicShares, vss } = setup;
    partialPermutations(publicShares).forEach(async (qualifiedShares) => {
      const reconstructed = await vss.reconstructPublic(qualifiedShares);
      expect(await reconstructed.equals(publicKey)).toBe(
        qualifiedShares.length >= threshold
      );
    });
  });
  test('Public reconstruction - with threshold check', async () => {
    const { publicKey, publicShares, vss } = setup;
    partialPermutations(publicShares, 0, threshold - 1).forEach(async (qualifiedShares) => {
      await expect(vss.reconstructPublic(qualifiedShares, threshold)).rejects.toThrow(
        'Insufficient number of shares'
      );
    });
    partialPermutations(publicShares, threshold, nrShares).forEach(async (qualifiedShares) => {
      const reconstructed = await vss.reconstructPublic(qualifiedShares, threshold);
      expect(await reconstructed.equals(publicKey)).toBe(true);
    });
  });
});
