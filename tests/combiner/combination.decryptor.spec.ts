import { combinePartialDecryptors } from 'vsslib/combiner';
import { cartesian, partialPermutations, isEqualBuffer } from '../utils';
import { mockThresholdDecryptionSetup } from '../helpers';
import { resolveTestConfig } from '../environ';

const { systems, nrShares, threshold, elgamalSchemes: schemes} = resolveTestConfig();


describe('Combination of partial decryptors - unconditioned', () => {
  it.each(cartesian([systems, schemes]))('unconditioned - over %s/%s', async (system, scheme) => {
    const { ctx, ciphertext, decryptor: target, partialDecryptors } = await mockThresholdDecryptionSetup({
      scheme, system, nrShares, threshold
    });
    partialPermutations(partialDecryptors).forEach(async (qualifiedShares) => {
      const decryptor = await combinePartialDecryptors(ctx, qualifiedShares);
      expect(isEqualBuffer(decryptor, target)).toBe(
        qualifiedShares.length >= threshold
      );
    });
  });
  it.each(cartesian([systems, schemes]))('threshold guard - over %s/%s', async (system, scheme) => {
    const { ctx, ciphertext, decryptor: target, partialDecryptors } = await mockThresholdDecryptionSetup({
      scheme, system, nrShares, threshold
    });
    partialPermutations(partialDecryptors, 0, threshold - 1).forEach(async (qualifiedShares) => {
      await expect(combinePartialDecryptors(ctx, qualifiedShares, threshold)).rejects.toThrow(
        'Insufficient number of shares'
      );
    });
    partialPermutations(partialDecryptors, threshold, nrShares).forEach(async (qualifiedShares) => {
      const decryptor = await combinePartialDecryptors(ctx, qualifiedShares, threshold);
      expect(isEqualBuffer(decryptor, target)).toBe(true);
    });
  });
});
