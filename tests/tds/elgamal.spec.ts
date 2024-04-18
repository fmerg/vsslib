import { Point } from '../../src/backend/abstract'
import { key, backend } from '../../src';
import { PrivateKey, PublicKey, PrivateShare, PublicShare } from '../../src/key';
import { PartialDecryptor } from '../../src/tds';
import { Label } from '../../src/types';
import { ElgamalSchemes } from '../../src/enums';
import { partialPermutations } from '../helpers';
import tds from '../../src/tds';


const runSetup = async (opts: {
  label: Label,
  nrShares: number,
  threshold: number,
  invalidIndexes?: number[],
}) => {
  const { label, nrShares, threshold } = opts;
  const { privateKey, publicKey } = await key.generate(label);
  const sharing = await privateKey.distribute(nrShares, threshold);
  const privateShares = await sharing.getSecretShares();
  const publicShares = await sharing.getPublicShares();
  const point = await publicKey.ctx.randomPoint();
  const message = point.toBytes()
  const { ciphertext, decryptor } = await publicKey.encrypt(message, {
    scheme: ElgamalSchemes.PLAIN
  });
  const partialDecryptors = [];
  for (const privateShare of privateShares) {
    const share = await privateShare.generatePartialDecryptor(ciphertext);
    partialDecryptors.push(share);
  }
  const invalidDecryptors = [];
  const invalidIndexes = opts.invalidIndexes || [];
  if (invalidIndexes) {
    for (const share of partialDecryptors) {
      invalidDecryptors.push(!(invalidIndexes.includes(share.index)) ? share : {
        value: await privateKey.ctx.randomPoint(),
        index: share.index,
        proof: share.proof,
      });
    }
  }

  const ctx = backend.initGroup(label);
  const combiner = tds(ctx, threshold);
  return {
    privateKey,
    publicKey,
    privateShares,
    publicShares,
    message,
    ciphertext,
    decryptor,
    partialDecryptors,
    invalidDecryptors,
    invalidIndexes,
    combiner,
  }
}


describe('Partial decryptors validation', () => {
  const nrShares = 5;
  const threshold = 3;
  const label = 'ed25519' as Label;
  let setup: any;

  beforeAll(async () => {
    setup = await runSetup({ label, nrShares, threshold, invalidIndexes: [2, 3] });
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


describe('Decryptor reconstruction', () => {
  const nrShares = 3;
  const threshold = 2;
  const label = 'ed25519' as Label;
  let setup: any;

  beforeAll(async () => {
    setup = await runSetup({ label, nrShares, threshold });
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


describe('Threshold decryption', () => {
  const nrShares = 3;
  const threshold = 2;
  const label = 'ed25519' as Label;
  let setup: any;

  beforeAll(async () => {
    setup = await runSetup({ label, nrShares, threshold });
  });

  test('Skip threshold check', async () => {
    const { privateKey, message, ciphertext, partialDecryptors, combiner } = setup;
    partialPermutations(partialDecryptors).forEach(async (qualifiedSet) => {
      const plaintext1 = await combiner.decrypt(ciphertext, qualifiedSet, { skipThreshold: true });
      const plaintext2 = await privateKey.decrypt(ciphertext);
      if (qualifiedSet.length >= threshold) {
        expect(plaintext1).toEqual(message);
        expect(plaintext1).toEqual(plaintext2);
      } else {
        expect(plaintext1).not.toEqual(message);
        expect(plaintext1).not.toEqual(plaintext2);
      }
    });
  });
  test('With threshold check', async () => {
    const { privateKey, message, ciphertext, partialDecryptors, combiner } = setup;
    partialPermutations(partialDecryptors, 0, threshold - 1).forEach(async (qualifiedSet) => {
      await expect(combiner.decrypt(ciphertext, qualifiedSet)).rejects.toThrow('Nr shares less than threshold');
    });
    partialPermutations(partialDecryptors, threshold, nrShares).forEach(async (qualifiedSet) => {
      const plaintext = await combiner.decrypt(ciphertext, qualifiedSet);
      expect(plaintext).toEqual(message);
    });
  });
});
