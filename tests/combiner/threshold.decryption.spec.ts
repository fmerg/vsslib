import { ElgamalSchemes } from 'vsslib/enums';
import { thresholdDecrypt } from 'vsslib/combiner';
import { cartesian, partialPermutations, isEqualBuffer } from '../utils';
import { mockThresholdDecryptionSetup } from '../helpers';
import { resolveTestConfig } from '../environ';

const { systems, nrShares, threshold, elgamalSchemes: schemes} = resolveTestConfig();

describe('Threshold decryption', () => {
  it.each(cartesian([systems, schemes]))(
    'success - unconditioned - without nonce - over %s/%s', async (system, scheme) => {
    const { privateKey, message, ciphertext, partialPublicKeys, partialDecryptors, ctx } = await mockThresholdDecryptionSetup({
      scheme, system, nrShares, threshold
    });
    switch(scheme) {
      case ElgamalSchemes.PLAIN:
        partialPermutations(partialDecryptors).forEach(async (qualifiedShares) => {
          const { plaintext } = await thresholdDecrypt(ctx, ciphertext, qualifiedShares, partialPublicKeys, { scheme });
          expect(isEqualBuffer(plaintext, message)).toBe(qualifiedShares.length >= threshold);
        });
        break;
      case ElgamalSchemes.DHIES:
      case ElgamalSchemes.HYBRID:
        partialPermutations(partialDecryptors).forEach(async (qualifiedShares) => {
          if (qualifiedShares.length >= threshold) {
            const { plaintext } = await thresholdDecrypt(ctx, ciphertext, qualifiedShares, partialPublicKeys, { scheme });
            expect(plaintext).toEqual(message);
          } else {
            await expect(thresholdDecrypt(ctx, ciphertext, qualifiedShares, partialPublicKeys, { scheme })).rejects.toThrow(
              scheme == ElgamalSchemes.HYBRID ?
                'Could not decrypt: AES decryption failure' :
                'Could not decrypt: Invalid MAC'
            );
          }
        });
    }
  });
  it.each(cartesian([systems, schemes]))(
    'success - unconditioned - with nonce - over %s/%s', async (system, scheme) => {
    const { privateKey, message, ciphertext, partialPublicKeys, partialDecryptors, ctx, nonces } = await mockThresholdDecryptionSetup({
      scheme, system, nrShares, threshold, withNonce: true
    });
    switch(scheme) {
      case ElgamalSchemes.PLAIN:
        partialPermutations(partialDecryptors).forEach(async (qualifiedShares) => {
          const { plaintext } = await thresholdDecrypt(
            ctx, ciphertext, qualifiedShares, partialPublicKeys, { scheme, nonces }
          );
          expect(isEqualBuffer(plaintext, message)).toBe(qualifiedShares.length >= threshold);
        });
        break;
      case ElgamalSchemes.DHIES:
      case ElgamalSchemes.HYBRID:
        partialPermutations(partialDecryptors).forEach(async (qualifiedShares) => {
          if (qualifiedShares.length >= threshold) {
            const { plaintext } = await thresholdDecrypt(
              ctx, ciphertext, qualifiedShares, partialPublicKeys, { scheme, nonces }
            );
            expect(plaintext).toEqual(message);
          } else {
            await expect(
              thresholdDecrypt(
                ctx, ciphertext, qualifiedShares, partialPublicKeys, { scheme, nonces }
              )
            ).rejects.toThrow(
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
    const { privateKey, message, ciphertext, partialPublicKeys, partialDecryptors, ctx } = await mockThresholdDecryptionSetup({
      scheme, system, nrShares, threshold
    });
    partialPermutations(partialDecryptors, 0, threshold - 1).forEach(async (qualifiedShares) => {
      await expect(
        thresholdDecrypt(ctx, ciphertext, qualifiedShares, partialPublicKeys, { scheme, threshold })
      ).rejects.toThrow('Insufficient number of shares');
    });
    partialPermutations(partialDecryptors, threshold, nrShares).forEach(async (qualifiedShares) => {
      const { plaintext } = await thresholdDecrypt(ctx, ciphertext, qualifiedShares, partialPublicKeys, {
        scheme, threshold
      });
      expect(plaintext).toEqual(message);
    });
  });
  it.each(cartesian([systems, schemes])
  )('failure - error on invalid - forged proof - over %s/%s', async (system, scheme) => {
    const { ctx, privateKey, message, ciphertext, partialPublicKeys, partialDecryptors } = await mockThresholdDecryptionSetup({
      scheme, system, nrShares, threshold, nrInvalid: 2
    });
    await expect(
      thresholdDecrypt(ctx, ciphertext, partialDecryptors, partialPublicKeys, { scheme, threshold })
    ).rejects.toThrow('Invalid partial decryptor with index');
  });
  it.each(cartesian([systems, schemes])
  )('failure - error on invalid - forged nonce - over %s/%s', async (system, scheme) => {
    const { ctx, privateKey, message, ciphertext, partialPublicKeys, partialDecryptors, nonces } = await mockThresholdDecryptionSetup({
      scheme, system, nrShares, threshold, nrInvalid: 2, withNonce: true
    });
    await expect(
      thresholdDecrypt(ctx, ciphertext, partialDecryptors, partialPublicKeys, { scheme, threshold, nonces })
    ).rejects.toThrow('Invalid partial decryptor with index');
  });
  it.each(cartesian([systems, schemes]))
  ('failure - accurate blaming - forged proof - over %s/%s', async (system, scheme) => {
    const {
      ctx, partialPublicKeys, message, ciphertext, partialDecryptors, decryptor, blame: targetBlame
    } = await mockThresholdDecryptionSetup({
      scheme, system, nrShares, threshold, nrInvalid: 2
    });
    const { plaintext, blame } = await thresholdDecrypt(ctx, ciphertext, partialDecryptors, partialPublicKeys, {
      scheme, threshold, errorOnInvalid: false
    });
    expect(isEqualBuffer(plaintext, Uint8Array.from([]))).toBe(true);
    expect(blame.map(b => b.index).sort()).toEqual(targetBlame.sort());
  });
  it.each(cartesian([systems, schemes]))
  ('failure - accurate blaming - forged nonce - over %s/%s', async (system, scheme) => {
    const {
      ctx, partialPublicKeys, message, ciphertext, partialDecryptors, decryptor, blame: targetBlame, nonces
    } = await mockThresholdDecryptionSetup({
      scheme, system, nrShares, threshold, nrInvalid: 2, withNonce: true
    });
    const { plaintext, blame } = await thresholdDecrypt(ctx, ciphertext, partialDecryptors, partialPublicKeys, {
      scheme, threshold, errorOnInvalid: false, nonces
    });
    expect(isEqualBuffer(plaintext, Uint8Array.from([]))).toBe(true);
    expect(blame.map(b => b.index).sort()).toEqual(targetBlame.sort());
  });
  it.each(cartesian([systems, schemes]))(
    'failure - missing public - over %s/%s', async (system, scheme) => {
    const { ctx, partialPublicKeys, ciphertext, partialDecryptors, decryptor } = await mockThresholdDecryptionSetup({
      scheme, system, nrShares, threshold
    });
    await expect(
      thresholdDecrypt(
        ctx, ciphertext, partialDecryptors, partialPublicKeys.slice(0, nrShares - 1), { scheme, threshold }
      )
    ).rejects.toThrow('No public share with index')
  });
  it.each(cartesian([systems, schemes]))(
    'failure - missing nonce - over %s/%s', async (system, scheme) => {
    const { ctx, partialPublicKeys, ciphertext, partialDecryptors, decryptor, nonces } = await mockThresholdDecryptionSetup({
      scheme, system, nrShares, threshold, withNonce: true
    });
    await expect(
      thresholdDecrypt(
        ctx, ciphertext, partialDecryptors, partialPublicKeys, {
          scheme, threshold, nonces: nonces.slice(0, nrShares - 1)
        }
      )
    ).rejects.toThrow('No nonce for index')
  });
});
