import { ElgamalSchemes } from '../../src/enums';
import { thresholdDecrypt } from '../../src/combiner';
import { cartesian, partialPermutations, isEqualBuffer } from '../utils';
import { createThresholdDecryptionSetup } from '../helpers';
import { resolveTestConfig } from '../environ';

const { systems, nrShares, threshold, elgamalSchemes: schemes} = resolveTestConfig();

describe('Threshold decryption', () => {
  it.each(cartesian([systems, schemes]))(
    'success - unconditioned - over %s/%s', async (system, scheme) => {
    const { privateKey, message, ciphertext, publicShares, partialDecryptors, ctx } = await createThresholdDecryptionSetup({
      scheme, system, nrShares, threshold
    });
    switch(scheme) {
      case ElgamalSchemes.PLAIN:
        partialPermutations(partialDecryptors).forEach(async (qualifiedShares) => {
          const { plaintext } = await thresholdDecrypt(ctx, ciphertext, qualifiedShares, publicShares, { scheme });
          expect(isEqualBuffer(plaintext, message)).toBe(qualifiedShares.length >= threshold);
        });
        break;
      case ElgamalSchemes.DHIES:
      case ElgamalSchemes.HYBRID:
        partialPermutations(partialDecryptors).forEach(async (qualifiedShares) => {
          if (qualifiedShares.length >= threshold) {
            const { plaintext } = await thresholdDecrypt(ctx, ciphertext, qualifiedShares, publicShares, { scheme });
            expect(plaintext).toEqual(message);
          } else {
            await expect(thresholdDecrypt(ctx, ciphertext, qualifiedShares, publicShares, { scheme })).rejects.toThrow(
              scheme == ElgamalSchemes.HYBRID ?
                'Could not decrypt: AES decryption failure' :
                'Could not decrypt: Invalid MAC'
            );
          }
        });
    }
  });
  it.each(cartesian([systems, schemes]))(
    'success - threshold guard - over %s/%s', async (system, scheme) => {
    const { privateKey, message, ciphertext, publicShares, partialDecryptors, ctx } = await createThresholdDecryptionSetup({
      scheme, system, nrShares, threshold
    });
    partialPermutations(partialDecryptors, 0, threshold - 1).forEach(async (qualifiedShares) => {
      await expect(
        thresholdDecrypt(ctx, ciphertext, qualifiedShares, publicShares, { scheme, threshold })
      ).rejects.toThrow('Insufficient number of shares');
    });
    partialPermutations(partialDecryptors, threshold, nrShares).forEach(async (qualifiedShares) => {
      const { plaintext } = await thresholdDecrypt(ctx, ciphertext, qualifiedShares, publicShares, {
        scheme, threshold
      });
      expect(plaintext).toEqual(message);
    });
  });
  it.each(cartesian([systems, schemes])
  )('failure - error on invalid - over %s/%s', async (system, scheme) => {
    const { ctx, privateKey, message, ciphertext, publicShares, partialDecryptors, invalidDecryptors } = await createThresholdDecryptionSetup({
      scheme, system, nrShares, threshold, nrInvalidIndexes: 2
    });
    await expect(
      thresholdDecrypt(ctx, ciphertext, invalidDecryptors, publicShares, { scheme, threshold })
    ).rejects.toThrow('Invalid partial decryptor with index');
  });
  it.each(cartesian([systems, schemes]))
  ('failure - with blame - over %s/%s', async (system, scheme) => {
    const {
      ctx, publicShares, message, ciphertext, partialDecryptors, invalidDecryptors, decryptor, blame: targetBlame
    } = await createThresholdDecryptionSetup({
      scheme, system, nrShares, threshold, nrInvalidIndexes: 2
    });
    const { plaintext, blame } = await thresholdDecrypt(ctx, ciphertext, invalidDecryptors, publicShares, {
      scheme, threshold, errorOnInvalid: false
    });
    expect(isEqualBuffer(plaintext, Uint8Array.from([]))).toBe(true);
    expect(blame.sort()).toEqual(targetBlame.sort());
  });
  it.each(cartesian([systems, schemes]))(
    'failure - missing public - over %s/%s', async (system, scheme) => {
    const { ctx, publicShares, ciphertext, partialDecryptors, decryptor } = await createThresholdDecryptionSetup({
      scheme, system, nrShares, threshold
    });
    await expect(
      thresholdDecrypt(
        ctx, ciphertext, partialDecryptors, publicShares.slice(0, nrShares - 1), { scheme, threshold }
      )
    ).rejects.toThrow('No public share with index')
  });
});
