import { ElgamalSchemes } from '../../src/schemes';
import { ErrorMessages } from '../../src/errors';
import {
  verifyPartialDecryptors,
  reconstructDecryptor,
  thresholdDecrypt,
} from '../../src/core';
import { partialPermutations } from '../helpers';
import { createThresholdDecryptionSetup } from './helpers';
import { resolveTestConfig } from '../environ';

const { label, nrShares, threshold } = resolveTestConfig();

const scheme = ElgamalSchemes.KEM;

describe(`Partial decryptors validation over ${label}`, () => {
  let setup: any;

  beforeAll(async () => {
    setup = await createThresholdDecryptionSetup({
      scheme, label, nrShares, threshold, invalidIndexes: [2, 3]
    });
  });

  test('Success', async () => {
    const { ctx, publicShares, ciphertext, partialDecryptors } = setup
    const { flag, indexes } = await verifyPartialDecryptors(
      ctx, ciphertext, publicShares, partialDecryptors
    );
    expect(flag).toBe(true);
    expect(indexes).toEqual([]);
  });
  test('Failure - not raise on invalid', async () => {
    const { ctx, publicShares, ciphertext, invalidDecryptors, invalidIndexes } = setup
    const { flag, indexes } = await verifyPartialDecryptors(
      ctx, ciphertext, publicShares, invalidDecryptors
    );
    expect(flag).toBe(false);
    expect(indexes).toEqual(invalidIndexes);
  });
  test('Failure - raise on invalid', async () => {
    const { ctx, publicShares, ciphertext, invalidDecryptors } = setup
    await expect(
      verifyPartialDecryptors(ctx, ciphertext, publicShares, invalidDecryptors, {
        threshold, raiseOnInvalid: true
      })
    ).rejects.toThrow(ErrorMessages.INVALID_PARTIAL_DECRYPTOR);
  });
  test('Failure - less than threshold', async () => {
    const { ctx, publicShares, ciphertext, partialDecryptors } = setup
    await expect(
      verifyPartialDecryptors(
        ctx, ciphertext, publicShares, partialDecryptors.slice(0, threshold - 1), { threshold }
      )
    ).rejects.toThrow(ErrorMessages.INSUFFICIENT_NR_SHARES);
  });
  test('Success - skip threshold check', async () => {
    const { ctx, publicShares, ciphertext, partialDecryptors } = setup
    const { flag, indexes } = await verifyPartialDecryptors(
      ctx, ciphertext, publicShares, partialDecryptors.slice(0, threshold - 1),
    )
    expect(flag).toBe(true);
    expect(indexes).toEqual([]);
  });
});


describe(`Decryptor reconstruction over ${label}`, () => {
  let setup: any;

  beforeAll(async () => {
    setup = await createThresholdDecryptionSetup({ scheme, label, nrShares, threshold });
  });

  test('Skip threshold check', async () => {
    const { ctx, ciphertext, decryptor: targetDecryptor, partialDecryptors } = setup;
    partialPermutations(partialDecryptors).forEach(async (qualifiedShares) => {
      const decryptor = await reconstructDecryptor(ctx, qualifiedShares);
      expect(await decryptor.equals(targetDecryptor)).toBe(qualifiedShares.length >= threshold);
    });
  });
  test('With threshold check', async () => {
    const { ctx, ciphertext, decryptor: targetDecryptor, partialDecryptors } = setup;
    partialPermutations(partialDecryptors, 0, threshold - 1).forEach(async (qualifiedShares) => {
      await expect(reconstructDecryptor(ctx, qualifiedShares, { threshold })).rejects.toThrow(
        ErrorMessages.INSUFFICIENT_NR_SHARES
      );
    });
    partialPermutations(partialDecryptors, threshold, nrShares).forEach(async (qualifiedShares) => {
      const decryptor = await reconstructDecryptor(ctx, qualifiedShares, { threshold });
      expect(await decryptor.equals(targetDecryptor)).toBe(true);
    });
  });
});


describe(`Threshold decryption over ${label}`, () => {
  let setup: any;

  beforeAll(async () => {
    setup = await createThresholdDecryptionSetup({ scheme, label, nrShares, threshold });
  });

  test('Skip threshold check', async () => {
    const { privateKey, message, ciphertext, partialDecryptors, ctx } = setup;
    partialPermutations(partialDecryptors).forEach(async (qualifiedShares) => {
      if (qualifiedShares.length >= threshold) {
        const plaintext1 = await thresholdDecrypt(ctx, ciphertext, qualifiedShares, { scheme });
        expect(plaintext1).toEqual(message);
        const plaintext2 = await privateKey.decrypt(ciphertext, { scheme });
        expect(plaintext1).toEqual(plaintext2);
      } else {
        await expect(thresholdDecrypt(ctx, ciphertext, qualifiedShares, { scheme })).rejects.toThrow(
          'Could not decrypt: AES decryption failure'
        );
      }
    });
  });
  test('With threshold check', async () => {
    const { privateKey, message, ciphertext, partialDecryptors, ctx } = setup;
    partialPermutations(partialDecryptors, 0, threshold - 1).forEach(async (qualifiedShares) => {
      await expect(
        thresholdDecrypt(ctx, ciphertext, qualifiedShares, { scheme, threshold })
      ).rejects.toThrow(ErrorMessages.INSUFFICIENT_NR_SHARES);
    });
    partialPermutations(partialDecryptors, threshold, nrShares).forEach(async (qualifiedShares) => {
      const plaintext = await thresholdDecrypt(ctx, ciphertext, qualifiedShares, { scheme, threshold });
      expect(plaintext).toEqual(message);
    });
  });
});
