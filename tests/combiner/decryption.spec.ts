import { Point } from '../../src/backend/abstract';
import { ElgamalSchemes } from '../../src/enums';
import {
  verifyPartialDecryptors,
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
  it.each(cartesian([systems, schemes]))('Failure - not error on invalid - over %s/%s', async (
    system, scheme
  ) => {
    const {
      ctx, publicShares, ciphertext, partialDecryptors, invalidDecryptors, blame: targetBlame
    } = await createThresholdDecryptionSetup({
      scheme, system, nrShares, threshold, nrInvalidIndexes: 2
    });
    const { flag, indexes } = await verifyPartialDecryptors(
      ctx, ciphertext, publicShares, invalidDecryptors
    );
    expect(flag).toBe(false);
    expect(indexes.sort()).toEqual(targetBlame.sort());
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
      verifyPartialDecryptors(ctx, ciphertext, publicShares, invalidDecryptors, {
        threshold, errorOnInvalid: true
      })
    ).rejects.toThrow('Invalid partial decryptor');
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
    ).rejects.toThrow('Insufficient number of shares');
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


describe('Decryptor recovery', () => {
  it.each(cartesian([systems, schemes]))('Skip threshold check over %s/%s', async (system, scheme) => {
    const { ctx, ciphertext, decryptor: targetDecryptor, partialDecryptors } = await createThresholdDecryptionSetup({
      scheme, system, nrShares, threshold
    });
    partialPermutations(partialDecryptors).forEach(async (qualifiedShares) => {
      const decryptor = await recoverDecryptor(ctx, qualifiedShares);
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
      await expect(recoverDecryptor(ctx, qualifiedShares, { threshold })).rejects.toThrow(
        'Insufficient number of shares'
      );
    });
    partialPermutations(partialDecryptors, threshold, nrShares).forEach(async (qualifiedShares) => {
      const decryptor = await recoverDecryptor(ctx, qualifiedShares, { threshold });
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
      case ElgamalSchemes.DHIES:
      case ElgamalSchemes.HYBRID:
        partialPermutations(partialDecryptors).forEach(async (qualifiedShares) => {
          if (qualifiedShares.length >= threshold) {
            const plaintext = await thresholdDecrypt(ctx, ciphertext, qualifiedShares, { scheme });
            expect(plaintext).toEqual(message);
          } else {
            await expect(thresholdDecrypt(ctx, ciphertext, qualifiedShares, { scheme })).rejects.toThrow(
              scheme == ElgamalSchemes.HYBRID ?
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
      ).rejects.toThrow('Insufficient number of shares');
    });
    partialPermutations(partialDecryptors, threshold, nrShares).forEach(async (qualifiedShares) => {
      const plaintext = await thresholdDecrypt(ctx, ciphertext, qualifiedShares, {
        scheme, threshold
      });
      expect(plaintext).toEqual(message);
    });
  });
});
