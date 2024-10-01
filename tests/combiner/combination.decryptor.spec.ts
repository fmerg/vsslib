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
    partialPermutations(partialDecryptors).forEach(async (shares) => {
      const decryptor = await combinePartialDecryptors(ctx, shares);
      expect(isEqualBuffer(decryptor, target)).toBe(
        shares.length >= threshold
      );
    });
  });
  it.each(cartesian([systems, schemes]))('threshold guard - over %s/%s', async (system, scheme) => {
    const { ctx, ciphertext, decryptor: target, partialDecryptors } = await mockThresholdDecryptionSetup({
      scheme, system, nrShares, threshold
    });
    partialPermutations(partialDecryptors, 0, threshold - 1).forEach(async (shares) => {
      await expect(combinePartialDecryptors(ctx, shares, threshold)).rejects.toThrow(
        'Insufficient number of shares'
      );
    });
    partialPermutations(partialDecryptors, threshold, nrShares).forEach(async (shares) => {
      const decryptor = await combinePartialDecryptors(ctx, shares, threshold);
      expect(isEqualBuffer(decryptor, target)).toBe(true);
    });
  });
});
