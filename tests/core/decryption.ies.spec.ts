import { ElgamalSchemes } from '../../src/enums';
import { ErrorMessages } from '../../src/errors';
import {
  verifyPartialDecryptors,
  reconstructDecryptor,
  thresholdDecrypt,
} from '../../src/core';
import { partialPermutations, isEqualBuffer } from '../helpers';
import { createThresholdDecryptionSetup, selectShare } from './helpers';
import { resolveTestConfig } from '../environ';

const { system, nrShares, threshold } = resolveTestConfig();

const scheme = ElgamalSchemes.IES;


describe(`Single partial decryptor verification over ${system}`, () => {
  let setup: any;
  beforeAll(async () => {
    setup = await createThresholdDecryptionSetup({
      scheme, system, nrShares, threshold, nrInvalidIndexes: 2
    });
  });

  test('Partial decryptor verification - success', async () => {
    const { ctx, publicShares, ciphertext, partialDecryptors } = setup
    for (const share of partialDecryptors) {
      const publicShare = selectShare(share.index, publicShares);
      const verified = await publicShare.verifyPartialDecryptor(
        ciphertext, share
      );
      expect(verified).toBe(true);
    }
  });
  test('Partial decryptor verification - failure', async () => {
    const { ctx, publicShares, ciphertext, partialDecryptors } = setup
    const forgedCiphertext = {
      alpha: ciphertext.alpha,
      beta: (await ctx.randomPoint()).toBytes(),
    };
    for (const share of partialDecryptors) {
      const publicShare = selectShare(share.index, publicShares);
      await expect(
        publicShare.verifyPartialDecryptor(forgedCiphertext, share)
      ).rejects.toThrow(
        ErrorMessages.INVALID_PARTIAL_DECRYPTOR
      );
    }
  });
})

describe(`Partial decryptors verification over ${system}`, () => {
  let setup: any;

  beforeAll(async () => {
    setup = await createThresholdDecryptionSetup({
      scheme, system, nrShares, threshold, nrInvalidIndexes: 2
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
    expect(indexes.sort()).toEqual(invalidIndexes.sort());
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


describe(`Decryptor reconstruction over ${system}`, () => {
  let setup: any;

  beforeAll(async () => {
    setup = await createThresholdDecryptionSetup({ scheme, system, nrShares, threshold });
  });

  test('Skip threshold check', async () => {
    const { ctx, ciphertext, decryptor: targetDecryptor, partialDecryptors } = setup;
    partialPermutations(partialDecryptors).forEach(async (qualifiedShares) => {
      const decryptor = await reconstructDecryptor(ctx, qualifiedShares);
      expect(isEqualBuffer(decryptor, targetDecryptor)).toBe(
        qualifiedShares.length >= threshold
      );
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
      expect(isEqualBuffer(decryptor, targetDecryptor)).toBe(true);
    });
  });
});


describe(`Threshold decryption over ${system}`, () => {
  let setup: any;

  beforeAll(async () => {
    setup = await createThresholdDecryptionSetup({ scheme, system, nrShares, threshold });
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
          'Could not decrypt: Invalid MAC'
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
      const plaintext = await thresholdDecrypt(ctx, ciphertext, qualifiedShares, {
        scheme, threshold
      });
      expect(plaintext).toEqual(message);
    });
  });
});
