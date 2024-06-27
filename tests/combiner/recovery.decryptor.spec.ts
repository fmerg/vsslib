import { recoverDecryptor } from '../../src/combiner';
import { cartesian, partialPermutations, isEqualBuffer } from '../utils';
import { createThresholdDecryptionSetup } from '../helpers';
import { resolveTestConfig } from '../environ';

const { systems, nrShares, threshold, elgamalSchemes: schemes} = resolveTestConfig();


describe('Decryptor recovery', () => {
  it.each(cartesian([systems, schemes])
  )('success - unconditioned - over %s/%s', async (system, scheme) => {
    const { ctx, publicShares, ciphertext, partialDecryptors, decryptor} = await createThresholdDecryptionSetup({
      scheme, system, nrShares, threshold
    });
    partialPermutations(partialDecryptors).forEach(async (qualifiedShares) => {
      const { result, blame } = await recoverDecryptor(ctx, qualifiedShares, ciphertext, publicShares);
      expect(isEqualBuffer(result, decryptor)).toBe(qualifiedShares.length >= threshold);
      expect(blame).toEqual([]);
    });
  });
  it.each(cartesian([systems, schemes])
  )('success - threshold guard - over %s/%s', async (system, scheme) => {
    const { ctx, publicShares, ciphertext, partialDecryptors, decryptor} = await createThresholdDecryptionSetup({
      scheme, system, nrShares, threshold
    });
    partialPermutations(partialDecryptors, 0, threshold - 1).forEach(async (qualifiedShares) => {
      await expect(recoverDecryptor(ctx, qualifiedShares, ciphertext, publicShares, { threshold })).rejects.toThrow(
        'Insufficient number of shares'
      );
    });
    partialPermutations(partialDecryptors, threshold, nrShares).forEach(async (qualifiedShares) => {
      const { result, blame } = await recoverDecryptor(ctx, qualifiedShares, ciphertext, publicShares);
      expect(isEqualBuffer(result, decryptor)).toBe(qualifiedShares.length >= threshold);
      expect(blame).toEqual([]);
    });
  });
  it.each(cartesian([systems, schemes])
  )('failure - error on invalid - over %s/%s', async (system, scheme) => {
    const {
      ctx, publicShares, ciphertext, partialDecryptors, invalidDecryptors
    } = await createThresholdDecryptionSetup({
      scheme, system, nrShares, threshold, nrInvalidIndexes: 2
    });
    await expect(
      recoverDecryptor(
        ctx, invalidDecryptors, ciphertext, publicShares, { threshold }
      )
    ).rejects.toThrow('Invalid partial decryptor');
  });
  it.each(cartesian([systems, schemes]))
  ('failure - with blame - over %s/%s', async (system, scheme) => {
    const {
      ctx, publicShares, ciphertext, partialDecryptors, invalidDecryptors, decryptor, blame: targetBlame
    } = await createThresholdDecryptionSetup({
      scheme, system, nrShares, threshold, nrInvalidIndexes: 2
    });
    const { result, blame } = await recoverDecryptor(
      ctx, invalidDecryptors, ciphertext, publicShares, { errorOnInvalid: false }
    );
    expect(isEqualBuffer(result, decryptor)).toBe(false);
    expect(blame.sort()).toEqual(targetBlame.sort());
  });
  it.each(cartesian([systems, schemes]))(
    'failure - missing public - over %s/%s', async (system, scheme) => {
    const { ctx, publicShares, ciphertext, partialDecryptors, decryptor } = await createThresholdDecryptionSetup({
      scheme, system, nrShares, threshold
    });
    await expect(
      recoverDecryptor(
        ctx, partialDecryptors, ciphertext, publicShares.slice(0, nrShares - 1)
      )
    ).rejects.toThrow('No public share with index')
  });
});
