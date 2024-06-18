import { Point } from '../../src/backend/abstract';
import { ElgamalSchemes } from '../../src/enums';
import {
  combinePartialDecryptors,
  recoverDecryptor,
  thresholdDecrypt,
} from '../../src/combiner';
import { cartesian, partialPermutations, isEqualBuffer } from '../utils';
import { createThresholdDecryptionSetup, selectPublicKeyShare } from '../helpers';
import { resolveTestConfig } from '../environ';

const { systems, nrShares, threshold, elgamalSchemes: schemes} = resolveTestConfig();


describe('Single partial decryptor verification', () => {
  it.each(cartesian([systems, schemes]))('Success over %s/%s', async (system, scheme) => {
    const { ctx, publicShares, ciphertext, partialDecryptors } = await createThresholdDecryptionSetup({
      scheme, system, nrShares, threshold
    });
    for (const share of partialDecryptors) {
      const publicShare = selectPublicKeyShare(share.index, publicShares);
      const verified = await publicShare.verifyPartialDecryptor(
        ciphertext, share
      );
      expect(verified).toBe(true);
    }
  });
  it.each(cartesian([systems, schemes]))('Failure over %s/%s', async (system, scheme) => {
    const { ctx, publicShares, ciphertext, partialDecryptors } = await createThresholdDecryptionSetup({
      scheme, system, nrShares, threshold
    });
    ciphertext.beta = (await ctx.randomPoint()).toBytes();
    for (const share of partialDecryptors) {
      const publicShare = selectPublicKeyShare(share.index, publicShares);
      await expect(
        publicShare.verifyPartialDecryptor(
          ciphertext,
          share
        )
      ).rejects.toThrow(
        'Invalid partial decryptor'
      );
    }
  });
});


describe('Combination of partial decryptors (no verification)', () => {
  it.each(cartesian([systems, schemes]))('no threshold guard - over %s/%s', async (system, scheme) => {
    const { ctx, ciphertext, decryptor: targetDecryptor, partialDecryptors } = await createThresholdDecryptionSetup({
      scheme, system, nrShares, threshold
    });
    partialPermutations(partialDecryptors).forEach(async (qualifiedShares) => {
      const decryptor = await combinePartialDecryptors(ctx, qualifiedShares);
      expect(isEqualBuffer(decryptor, targetDecryptor)).toBe(
        qualifiedShares.length >= threshold
      );
    });
  });
  it.each(cartesian([systems, schemes]))('with threshold guard - over %s/%s', async (system, scheme) => {
    const { ctx, ciphertext, decryptor: targetDecryptor, partialDecryptors } = await createThresholdDecryptionSetup({
      scheme, system, nrShares, threshold
    });
    partialPermutations(partialDecryptors, 0, threshold - 1).forEach(async (qualifiedShares) => {
      await expect(combinePartialDecryptors(ctx, qualifiedShares, threshold)).rejects.toThrow(
        'Insufficient number of shares'
      );
    });
    partialPermutations(partialDecryptors, threshold, nrShares).forEach(async (qualifiedShares) => {
      const decryptor = await combinePartialDecryptors(ctx, qualifiedShares, threshold);
      expect(isEqualBuffer(decryptor, targetDecryptor)).toBe(true);
    });
  });
});


describe('Decryptor recovery (includes verification)', () => {
  it.each(cartesian([systems, schemes]))('Success over %s/%s', async (system, scheme) => {
    const { ctx, publicShares, ciphertext, partialDecryptors, decryptor} = await createThresholdDecryptionSetup({
      scheme, system, nrShares, threshold
    });
    const { result, blame } = await recoverDecryptor(
      ctx, partialDecryptors, ciphertext, publicShares
    );
    expect(isEqualBuffer(result, decryptor)).toBe(true);
    expect(blame).toEqual([]);
  });
  it.each(cartesian([systems, schemes]))('Failure - error on invalid - over %s/%s', async (
    system, scheme
  ) => {
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
  it.each(cartesian([systems, schemes]))('Failure - no error on invalid - over %s/%s', async (
    system, scheme
  ) => {
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
  it.each(cartesian([systems, schemes]))('Failure - less than threshold - with threshold guard - over %s/%s', async (
    system, scheme
  ) => {
    const { ctx, publicShares, ciphertext, partialDecryptors } = await createThresholdDecryptionSetup({
      scheme, system, nrShares, threshold
    });
    await expect(
      recoverDecryptor(
        ctx, partialDecryptors.slice(0, threshold - 1), ciphertext, publicShares, { threshold }
      )
    ).rejects.toThrow('Insufficient number of shares');
  });
  it.each(cartesian([systems, schemes]))('Failure - less than threshold - no threshold guard - over %s/%s', async (
    system, scheme
  ) => {
    const { ctx, publicShares, ciphertext, partialDecryptors, decryptor } = await createThresholdDecryptionSetup({
      scheme, system, nrShares, threshold
    });
    const { result, blame } = await recoverDecryptor(
      ctx, partialDecryptors.slice(0, threshold - 1), ciphertext, publicShares
    )
    expect(isEqualBuffer(result, decryptor)).toBe(false);
    expect(blame).toEqual([]);
  });
  it.each(cartesian([systems, schemes]))('Failure - missing public key - over %s/%s', async (
    system, scheme
  ) => {
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


describe('Threshold decryption', () => {
  it.each(cartesian([systems, schemes]))('no threshold guard - over %s/%s', async (system, scheme) => {
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
  it.each(cartesian([systems, schemes]))('with threshold guard - over %s/%s', async (system, scheme) => {
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
});
