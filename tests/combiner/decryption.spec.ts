import { Point } from '../../src/backend/abstract';
import { ElgamalSchemes } from '../../src/enums';
import { ErrorMessages } from '../../src/errors';
import {
  verifyPartialDecryptors,
  reconstructDecryptor,
  thresholdDecrypt,
} from '../../src/combiner';
import { PrivateKeyShare, PublicKeyShare } from '../../src/keys';
import { cartesian, partialPermutations, isEqualBuffer } from '../utils';
import { createThresholdDecryptionSetup } from '../helpers';
import { resolveTestConfig } from '../environ';

const { systems, nrShares, threshold, elgamalSchemes: schemes} = resolveTestConfig();


export const selectPublicKeyShare = (index: number, shares: PublicKeyShare<Point>[]) =>
  shares.filter(share => share.index == index)[0];


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
        ErrorMessages.INVALID_PARTIAL_DECRYPTOR
      );
    }
  });
});


describe('Partial decryptors verification', () => {
  it.each(cartesian([systems, schemes]))('Success over %s/%s', async (system, scheme) => {
    const { ctx, publicShares, ciphertext, partialDecryptors } = await createThresholdDecryptionSetup({
      scheme, system, nrShares, threshold
    });
    const { flag, indexes } = await verifyPartialDecryptors(
      ctx, ciphertext, publicShares, partialDecryptors
    );
    expect(flag).toBe(true);
    expect(indexes).toEqual([]);
  });
  it.each(cartesian([systems, schemes]))('Failure - not raised on invalid - over %s/%s', async (
    system, scheme
  ) => {
    const {
      ctx, publicShares, ciphertext, partialDecryptors, invalidDecryptors, invalidIndexes
    } = await createThresholdDecryptionSetup({
      scheme, system, nrShares, threshold, nrInvalidIndexes: 2
    });
    const { flag, indexes } = await verifyPartialDecryptors(
      ctx, ciphertext, publicShares, invalidDecryptors
    );
    expect(flag).toBe(false);
    expect(indexes.sort()).toEqual(invalidIndexes.sort());
  });
  it.each(cartesian([systems, schemes]))('Failure - raised on invalid - over %s/%s', async (
    system, scheme
  ) => {
    const {
      ctx, publicShares, ciphertext, partialDecryptors, invalidDecryptors, invalidIndexes
    } = await createThresholdDecryptionSetup({
      scheme, system, nrShares, threshold, nrInvalidIndexes: 2
    });
    await expect(
      verifyPartialDecryptors(ctx, ciphertext, publicShares, invalidDecryptors, {
        threshold, errorOnInvalid: true
      })
    ).rejects.toThrow(ErrorMessages.INVALID_PARTIAL_DECRYPTOR);
  });
  it.each(cartesian([systems, schemes]))('Failure - less than threshold - over %s/%s', async (
    system, scheme
  ) => {
    const { ctx, publicShares, ciphertext, partialDecryptors } = await createThresholdDecryptionSetup({
      scheme, system, nrShares, threshold
    });
    await expect(
      verifyPartialDecryptors(
        ctx, ciphertext, publicShares, partialDecryptors.slice(0, threshold - 1), { threshold }
      )
    ).rejects.toThrow(ErrorMessages.INSUFFICIENT_NR_SHARES);
  });
  it.each(cartesian([systems, schemes]))('Failure - skip threshold check - over %s/%s', async (
    system, scheme
  ) => {
    const { ctx, publicShares, ciphertext, partialDecryptors } = await createThresholdDecryptionSetup({
      scheme, system, nrShares, threshold
    });
    const { flag, indexes } = await verifyPartialDecryptors(
      ctx, ciphertext, publicShares, partialDecryptors.slice(0, threshold - 1),
    )
    expect(flag).toBe(true);
    expect(indexes).toEqual([]);
  });
});


describe('Decryptor reconstruction', () => {
  it.each(cartesian([systems, schemes]))('Skip threshold check over %s/%s', async (system, scheme) => {
    const { ctx, ciphertext, decryptor: targetDecryptor, partialDecryptors } = await createThresholdDecryptionSetup({
      scheme, system, nrShares, threshold
    });
    partialPermutations(partialDecryptors).forEach(async (qualifiedShares) => {
      const decryptor = await reconstructDecryptor(ctx, qualifiedShares);
      expect(isEqualBuffer(decryptor, targetDecryptor)).toBe(
        qualifiedShares.length >= threshold
      );
    });
  });
  it.each(cartesian([systems, schemes]))('With threshold check over %s/%s', async (system, scheme) => {
    const { ctx, ciphertext, decryptor: targetDecryptor, partialDecryptors } = await createThresholdDecryptionSetup({
      scheme, system, nrShares, threshold
    });
    partialPermutations(partialDecryptors, 0, threshold - 1).forEach(async (qualifiedShares) => {
      await expect(reconstructDecryptor(ctx, qualifiedShares, { threshold })).rejects.toThrow(
        ErrorMessages.INSUFFICIENT_NR_SHARES
      );
    });
    partialPermutations(partialDecryptors, threshold, nrShares).forEach(async (qualifiedShares) => {
      const decryptor = await reconstructDecryptor(ctx, qualifiedShares, { threshold });
      expect(isEqualBuffer(decryptor, targetDecryptor)).toBe(true);
    });
  });
});


describe('Threshold decryption', () => {
  it.each(cartesian([systems, schemes]))('Skip threshold check over %s/%s', async (system, scheme) => {
    const { privateKey, message, ciphertext, partialDecryptors, ctx } = await createThresholdDecryptionSetup({
      scheme, system, nrShares, threshold
    });
    switch(scheme) {
      case ElgamalSchemes.PLAIN:
        partialPermutations(partialDecryptors).forEach(async (qualifiedShares) => {
          const plaintext = await thresholdDecrypt(ctx, ciphertext, qualifiedShares, { scheme });
          expect(isEqualBuffer(plaintext, message)).toBe(qualifiedShares.length >= threshold);
        });
        break;
      case ElgamalSchemes.IES:
      case ElgamalSchemes.KEM:
        partialPermutations(partialDecryptors).forEach(async (qualifiedShares) => {
          if (qualifiedShares.length >= threshold) {
            const plaintext = await thresholdDecrypt(ctx, ciphertext, qualifiedShares, { scheme });
            expect(plaintext).toEqual(message);
          } else {
            await expect(thresholdDecrypt(ctx, ciphertext, qualifiedShares, { scheme })).rejects.toThrow(
              scheme == ElgamalSchemes.KEM ?
                'Could not decrypt: AES decryption failure' :
                'Could not decrypt: Invalid MAC'
            );
          }
        });
    }
  });
  it.each(cartesian([systems, schemes]))('With threshold check over %s/%s', async (system, scheme) => {
    const { privateKey, message, ciphertext, partialDecryptors, ctx } = await createThresholdDecryptionSetup({
      scheme, system, nrShares, threshold
    });
    partialPermutations(partialDecryptors, 0, threshold - 1).forEach(async (qualifiedShares) => {
      await expect(
        thresholdDecrypt(ctx, ciphertext, qualifiedShares, { scheme, threshold })
      ).rejects.toThrow(ErrorMessages.INSUFFICIENT_NR_SHARES);
    });
    partialPermutations(partialDecryptors, threshold, nrShares).forEach(async (qualifiedShares) => {
      const plaintext = await thresholdDecrypt(ctx, ciphertext, qualifiedShares, {
        scheme, threshold
      });
      expect(plaintext).toEqual(message);
    });
  });
});
