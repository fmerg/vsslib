import { ElgamalSchemes } from '../../src/schemes';
import { ErrorMessages } from '../../src/errors';
import { partialPermutations } from '../helpers';
import { resolveBackend } from '../environ';
import { createThresholdDecryptionSetup } from './helpers';

const label = resolveBackend();
const scheme = ElgamalSchemes.KEM;
const nrShares = 5;
const threshold = 3;

describe(`Partial decryptors validation over ${label}`, () => {
  let setup: any;

  beforeAll(async () => {
    setup = await createThresholdDecryptionSetup({
      scheme, label, nrShares, threshold, invalidIndexes: [2, 3]
    });
  });

  test('Success', async () => {
    const { vss, publicShares, ciphertext, partialDecryptors } = setup
    const { flag, indexes } = await vss.verifyPartialDecryptors(
      ciphertext, publicShares, partialDecryptors
    );
    expect(flag).toBe(true);
    expect(indexes).toEqual([]);
  });
  test('Failure - not raise on invalid', async () => {
    const { vss, publicShares, ciphertext, invalidDecryptors, invalidIndexes } = setup
    const { flag, indexes } = await vss.verifyPartialDecryptors(
      ciphertext, publicShares, invalidDecryptors
    );
    expect(flag).toBe(false);
    expect(indexes).toEqual(invalidIndexes);
  });
  test('Failure - raise on invalid', async () => {
    const { vss, publicShares, ciphertext, invalidDecryptors } = setup
    await expect(
      vss.verifyPartialDecryptors(ciphertext, publicShares, invalidDecryptors, {
        threshold, raiseOnInvalid: true
      })
    ).rejects.toThrow(ErrorMessages.INVALID_PARTIAL_DECRYPTOR);
  });
  test('Failure - less than threshold', async () => {
    const { vss, publicShares, ciphertext, partialDecryptors } = setup
    await expect(
      vss.verifyPartialDecryptors(
        ciphertext, publicShares, partialDecryptors.slice(0, threshold - 1), { threshold }
      )
    ).rejects.toThrow(ErrorMessages.INSUFFICIENT_NR_SHARES);
  });
  test('Success - skip threshold check', async () => {
    const { vss, publicShares, ciphertext, partialDecryptors } = setup
    const { flag, indexes } = await vss.verifyPartialDecryptors(
      ciphertext, publicShares, partialDecryptors.slice(0, threshold - 1),
    )
    expect(flag).toBe(true);
    expect(indexes).toEqual([]);
  });
});


describe(`Decryptor reconstruction over ${label}`, () => {
  const nrShares = 3;
  const threshold = 2;
  let setup: any;

  beforeAll(async () => {
    setup = await createThresholdDecryptionSetup({ scheme, label, nrShares, threshold });
  });

  test('Skip threshold check', async () => {
    const { vss, ciphertext, decryptor: targetDecryptor, partialDecryptors } = setup;
    partialPermutations(partialDecryptors).forEach(async (qualifiedShares) => {
      const decryptor = await vss.reconstructDecryptor(qualifiedShares);
      expect(await decryptor.equals(targetDecryptor)).toBe(qualifiedShares.length >= threshold);
    });
  });
  test('With threshold check', async () => {
    const { vss, ciphertext, decryptor: targetDecryptor, partialDecryptors } = setup;
    partialPermutations(partialDecryptors, 0, threshold - 1).forEach(async (qualifiedShares) => {
      await expect(vss.reconstructDecryptor(qualifiedShares, { threshold })).rejects.toThrow(
        ErrorMessages.INSUFFICIENT_NR_SHARES
      );
    });
    partialPermutations(partialDecryptors, threshold, nrShares).forEach(async (qualifiedShares) => {
      const decryptor = await vss.reconstructDecryptor(qualifiedShares, { threshold });
      expect(await decryptor.equals(targetDecryptor)).toBe(true);
    });
  });
});


describe(`Threshold decryption over ${label}`, () => {
  const nrShares = 3;
  const threshold = 2;
  let setup: any;

  beforeAll(async () => {
    setup = await createThresholdDecryptionSetup({ scheme, label, nrShares, threshold });
  });

  test('Skip threshold check', async () => {
    const { privateKey, message, ciphertext, partialDecryptors, vss } = setup;
    partialPermutations(partialDecryptors).forEach(async (qualifiedShares) => {
      if (qualifiedShares.length >= threshold) {
        const plaintext1 = await vss.thresholdDecrypt(ciphertext, qualifiedShares, { scheme });
        expect(plaintext1).toEqual(message);
        const plaintext2 = await privateKey.decrypt(ciphertext, { scheme });
        expect(plaintext1).toEqual(plaintext2);
      } else {
        await expect(vss.thresholdDecrypt(ciphertext, qualifiedShares, { scheme })).rejects.toThrow(
          'Could not decrypt: AES decryption failure'
        );
      }
    });
  });
  test('With threshold check', async () => {
    const { privateKey, message, ciphertext, partialDecryptors, vss } = setup;
    partialPermutations(partialDecryptors, 0, threshold - 1).forEach(async (qualifiedShares) => {
      await expect(
        vss.thresholdDecrypt(ciphertext, qualifiedShares, { scheme, threshold })
      ).rejects.toThrow(ErrorMessages.INSUFFICIENT_NR_SHARES);
    });
    partialPermutations(partialDecryptors, threshold, nrShares).forEach(async (qualifiedShares) => {
      const plaintext = await vss.thresholdDecrypt(ciphertext, qualifiedShares, { scheme, threshold });
      expect(plaintext).toEqual(message);
    });
  });
});
