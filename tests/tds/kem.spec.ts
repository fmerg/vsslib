import { ElgamalSchemes, Label, ElgamalScheme } from '../../src/schemes';
import { Point } from '../../src/backend/abstract'
import { key, backend } from '../../src';
import { PrivateKey, PublicKey, PrivateShare, PublicShare } from '../../src/key';
import { PartialDecryptor } from '../../src/tds';
import { Combiner } from '../../src/tds';
import { partialPermutations } from '../helpers';
import { resolveBackend } from '../environ';
import { createThresholdDecryptionSetup } from './helpers';
import tds from '../../src/tds';



const label = resolveBackend();
const scheme = ElgamalSchemes.KEM;

describe(`Partial decryptors validation over ${label}`, () => {
  const nrShares = 5;
  const threshold = 3;
  let setup: any;

  beforeAll(async () => {
    setup = await createThresholdDecryptionSetup({
      scheme,
      label,
      nrShares,
      threshold,
      invalidIndexes: [2, 3]
    });
  });

  test('Success', async () => {
    const { combiner, publicShares, ciphertext, partialDecryptors } = setup
    const { flag, indexes } = await combiner.verifyPartialDecryptors(
      ciphertext, publicShares, partialDecryptors
    );
    expect(flag).toBe(true);
    expect(indexes).toEqual([]);
  });
  test('Failure - not raise on invalid', async () => {
    const { combiner, publicShares, ciphertext, invalidDecryptors, invalidIndexes } = setup
    const { flag, indexes } = await combiner.verifyPartialDecryptors(
      ciphertext, publicShares, invalidDecryptors
    );
    expect(flag).toBe(false);
    expect(indexes).toEqual(invalidIndexes);
  });
  test('Failure - raise on invalid', async () => {
    const { combiner, publicShares, ciphertext, invalidDecryptors } = setup
    await expect(
      combiner.verifyPartialDecryptors(ciphertext, publicShares, invalidDecryptors, {
        raiseOnInvalid: true
      })
    ).rejects.toThrow('Invalid partial decryptor');
  });
  test('Failure - less than threshold', async () => {
    const { combiner, publicShares, ciphertext, partialDecryptors } = setup
    await expect(
      combiner.verifyPartialDecryptors(ciphertext, publicShares, partialDecryptors.slice(0, threshold - 1))
    ).rejects.toThrow('Nr shares less than threshold');
  });
  test('Success - skip threshold check', async () => {
    const { combiner, publicShares, ciphertext, partialDecryptors } = setup
    const { flag, indexes } = await combiner.verifyPartialDecryptors(
      ciphertext, publicShares, partialDecryptors.slice(0, threshold - 1), { skipThreshold: true }
    )
    expect(flag).toBe(true);
    expect(indexes).toEqual([]);
  });
  test('Success - single valid', async () => {
    const { combiner, ciphertext, publicShares, partialDecryptors } = setup;
    for (const share of partialDecryptors) {
      const publicShare = publicShares.filter((pubShare: any) => pubShare.index == share.index)[0];
      const verified = await combiner.verifyPartialDecryptor(ciphertext, publicShare, share);
      expect(verified).toBe(true);
    }
  });
  test('Failure - single invalid', async () => {
    const { combiner, ciphertext, publicShares, invalidDecryptors, invalidIndexes } = setup;
    for (const share of invalidDecryptors) {
      const publicShare = publicShares.filter((pubShare: any) => pubShare.index == share.index)[0];
      if (invalidIndexes.includes(share.index))
        await expect(combiner.verifyPartialDecryptor(ciphertext, publicShare, share)).rejects.toThrow(
          'Invalid partial decryptor'
        );
      else expect(
        await combiner.verifyPartialDecryptor(ciphertext, publicShare, share)
      ).toBe(true)
    }
  });
});


describe(`Decryptor reconstruction over ${label}`, () => {
  const nrShares = 3;
  const threshold = 2;
  let setup: any;

  beforeAll(async () => {
    setup = await createThresholdDecryptionSetup({
      scheme,
      label,
      nrShares,
      threshold
    });
  });

  test('Skip threshold check', async () => {
    const { combiner, ciphertext, decryptor: expectedDecryptor, partialDecryptors } = setup;
    partialPermutations(partialDecryptors).forEach(async (qualifiedSet) => {
      const decryptor = await combiner.reconstructDecryptor(qualifiedSet, { skipThreshold: true });
      expect(await decryptor.equals(expectedDecryptor)).toBe(qualifiedSet.length >= threshold);
    });
  });
  test('With threshold check', async () => {
    const { combiner, ciphertext, decryptor: expectedDecryptor, partialDecryptors } = setup;
    partialPermutations(partialDecryptors, 0, threshold - 1).forEach(async (qualifiedSet) => {
      await expect(combiner.reconstructDecryptor(qualifiedSet)).rejects.toThrow('Nr shares less than threshold');
    });
    partialPermutations(partialDecryptors, threshold, nrShares).forEach(async (qualifiedSet) => {
      const decryptor = await combiner.reconstructDecryptor(qualifiedSet);
      expect(await decryptor.equals(expectedDecryptor)).toBe(true);
    });
  });
});


describe(`Threshold decryption over ${label}`, () => {
  const nrShares = 3;
  const threshold = 2;
  let setup: any;

  beforeAll(async () => {
    setup = await createThresholdDecryptionSetup({
      scheme,
      label,
      nrShares,
      threshold
    });
  });

  test('Skip threshold check', async () => {
    const { privateKey, message, ciphertext, partialDecryptors, combiner } = setup;
    partialPermutations(partialDecryptors).forEach(async (qualifiedSet) => {
      if (qualifiedSet.length >= threshold) {
        const plaintext1 = await combiner.decrypt(ciphertext, qualifiedSet, {
          scheme,
          skipThreshold: true,
        });
        const plaintext2 = await privateKey.decrypt(ciphertext, {
          scheme,
        });
        expect(plaintext1).toEqual(message);
        expect(plaintext1).toEqual(plaintext2);
      } else {
        await expect(
          combiner.decrypt(ciphertext, qualifiedSet, { scheme, skipThreshold: true })
        ).rejects.toThrow(
          'Could not decrypt: AES decryption failure'
        );
      }
    });
  });
  test('With threshold check', async () => {
    const { privateKey, message, ciphertext, partialDecryptors, combiner } = setup;
    partialPermutations(partialDecryptors, 0, threshold - 1).forEach(async (qualifiedSet) => {
      await expect(
        combiner.decrypt(ciphertext, qualifiedSet, { scheme })
      ).rejects.toThrow('Nr shares less than threshold');
    });
    partialPermutations(partialDecryptors, threshold, nrShares).forEach(async (qualifiedSet) => {
      const plaintext = await combiner.decrypt(ciphertext, qualifiedSet, { scheme });
      expect(plaintext).toEqual(message);
    });
  });
});
