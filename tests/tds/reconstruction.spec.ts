import { Label } from '../../src/schemes';
import { Point } from '../../src/backend/abstract'
import { key, backend } from '../../src';
import { PrivateKey, PublicKey, PrivateShare, PublicShare } from '../../src/key';
import { Combiner } from '../../src/tds';
import { partialPermutations } from '../helpers';
import { resolveBackend } from '../environ';
import { createKeyDistributionSetup } from './helpers';
import tds from '../../src/tds';


const label = resolveBackend();


describe(`Key reconstruction over ${label}`, () => {
  const nrShares = 5;
  const threshold = 3;
  let setup: any;

  beforeAll(async () => {
    setup = await createKeyDistributionSetup({
      label,
      nrShares,
      threshold,
    });
  });

  test('Private reconstruction - skip threshold check', async () => {
    const { privateKey, combiner, privateShares } = setup;
    partialPermutations(privateShares).forEach(async (qulifiedShares) => {
      const { privateKey: privateReconstructed } = await combiner.reconstructKey(
        qulifiedShares, { skipThreshold: true }
      );
      expect(await privateReconstructed.equals(privateKey)).toBe(qulifiedShares.length >= threshold);
    });
  });
  test('Private reconstruction - with threshold check', async () => {
    const { privateKey, combiner, privateShares } = setup;
    partialPermutations(privateShares, 0, threshold - 1).forEach(async (qulifiedShares) => {
      await expect(combiner.reconstructKey(qulifiedShares)).rejects.toThrow('Nr shares less than threshold');
    });
    partialPermutations(privateShares, threshold, nrShares).forEach(async (qulifiedShares) => {
      const { privateKey: privateReconstructed } = await combiner.reconstructKey(qulifiedShares);
      expect(await privateReconstructed.equals(privateKey)).toBe(true);
    });
  });
  test('Public reconstruction - skip threshold check', async () => {
    const { publicKey, combiner, publicShares } = setup;
    partialPermutations(publicShares).forEach(async (qulifiedShares) => {
      const publicReconstructed = await combiner.reconstructPublic(
        qulifiedShares, { skipThreshold: true }
      );
      expect(await publicReconstructed.equals(publicKey)).toBe(qulifiedShares.length >= threshold);
    });
  });
  test('Public reconstruction - with threshold check', async () => {
    const { publicKey, combiner, publicShares } = setup;
    partialPermutations(publicShares, 0, threshold - 1).forEach(async (qulifiedShares) => {
      await expect(combiner.reconstructPublic(qulifiedShares)).rejects.toThrow('Nr shares less than threshold');
    });
    partialPermutations(publicShares, threshold, nrShares).forEach(async (qulifiedShares) => {
      const publicReconstructed = await combiner.reconstructPublic(qulifiedShares);
      expect(await publicReconstructed.equals(publicKey)).toBe(true);
    });
  });
});
