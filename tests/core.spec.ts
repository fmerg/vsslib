import { Point } from '../src/backend/abstract'
import { key, backend } from '../src';
import { PrivateKey, PublicKey, PrivateShare, PublicShare } from '../src/key';
import { PartialDecryptor } from '../src/shamir';
import { Messages } from '../src/key/enums';
import { KeyDistribution } from '../src/key';
import { Ciphertext } from '../src/elgamal/core';
import { partialPermutations } from './helpers';
import { Combiner } from '../src/core';
import { Label } from '../src/types';

const core = require('../src/core');


const runSetup = async (opts: {
  label: Label,
  nrShares: number,
  threshold: number,
  invalidIndexes?: number[],
}) => {
  const { label, nrShares, threshold } = opts;
  const { privateKey, publicKey } = await key.generate(label);
  const distribution = await privateKey.distribute(nrShares, threshold);
  const { privateShares } = distribution;
  const publicShares = await distribution.publicShares();
  const message = await publicKey.ctx.randomPoint();
  const { ciphertext, decryptor } = await publicKey.encrypt(message);
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
  const combiner = core.initCombiner({ label, threshold });
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


describe('Key reconstruction', () => {
  const nrShares = 5;
  const threshold = 3;
  const label = 'ed25519' as Label;
  let setup: any;

  beforeAll(async () => {
    setup = await runSetup({ label, nrShares, threshold });
  });

  test('Private reconstruction - skip threshold check', async () => {
    const { privateKey, combiner, privateShares } = setup;
    partialPermutations(privateShares).forEach(async (qualifiedSet) => {
      const { privateKey: privateReconstructed } = await combiner.reconstructKey(
        qualifiedSet, { skipThreshold: true }
      );
      expect(await privateReconstructed.isEqual(privateKey)).toBe(qualifiedSet.length >= threshold);
    });
  });
  test('Private reconstruction - with threshold check', async () => {
    const { privateKey, combiner, privateShares } = setup;
    partialPermutations(privateShares, 0, threshold - 1).forEach(async (qualifiedSet) => {
      await expect(combiner.reconstructKey(qualifiedSet)).rejects.toThrow('Nr shares less than threshold');
    });
    partialPermutations(privateShares, threshold, nrShares).forEach(async (qualifiedSet) => {
      const { privateKey: privateReconstructed } = await combiner.reconstructKey(qualifiedSet);
      expect(await privateReconstructed.isEqual(privateKey)).toBe(true);
    });
  });
  test('Public reconstruction - skip threshold check', async () => {
    const { publicKey, combiner, publicShares } = setup;
    partialPermutations(publicShares).forEach(async (qualifiedSet) => {
      const publicReconstructed = await combiner.reconstructPublic(
        qualifiedSet, { skipThreshold: true }
      );
      expect(await publicReconstructed.isEqual(publicKey)).toBe(qualifiedSet.length >= threshold);
    });
  });
  test('Public reconstruction - with threshold check', async () => {
    const { publicKey, combiner, publicShares } = setup;
    partialPermutations(publicShares, 0, threshold - 1).forEach(async (qualifiedSet) => {
      await expect(combiner.reconstructPublic(qualifiedSet)).rejects.toThrow('Nr shares less than threshold');
    });
    partialPermutations(publicShares, threshold, nrShares).forEach(async (qualifiedSet) => {
      const publicReconstructed = await combiner.reconstructPublic(qualifiedSet);
      expect(await publicReconstructed.isEqual(publicKey)).toBe(true);
    });
  });
});


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
    const [verified, indexes] = await combiner.validatePartialDecryptors(
      ciphertext, publicShares, partialDecryptors
    );
    expect(verified).toBe(true);
    expect(indexes).toEqual([]);
  });
  test('Failure - not raise on invalid', async () => {
    const { combiner, publicShares, ciphertext, invalidDecryptors, invalidIndexes } = setup
    const [verified, indexes] = await combiner.validatePartialDecryptors(
      ciphertext, publicShares, invalidDecryptors
    );
    expect(verified).toBe(false);
    expect(indexes).toEqual(invalidIndexes);
  });
  test('Failure - raise on invalid', async () => {
    const { combiner, publicShares, ciphertext, invalidDecryptors } = setup
    await expect(
      combiner.validatePartialDecryptors(ciphertext, publicShares, invalidDecryptors, {
        raiseOnInvalid: true
      })
    ).rejects.toThrow('Invalid partial decryptor detected');
  });
  test('Failure - less than threshold', async () => {
    const { combiner, publicShares, ciphertext, partialDecryptors } = setup
    await expect(
      combiner.validatePartialDecryptors(ciphertext, publicShares, partialDecryptors.slice(0, threshold - 1))
    ).rejects.toThrow('Nr shares less than threshold');
  });
  test('Success - skip threshold check', async () => {
    const { combiner, publicShares, ciphertext, partialDecryptors } = setup
    const [verified, indexes] = await combiner.validatePartialDecryptors(
      ciphertext, publicShares, partialDecryptors.slice(0, threshold - 1), { skipThreshold: true }
    )
    expect(verified).toBe(true);
    expect(indexes).toEqual([]);
  });
  test('Success - single valid', async () => {
    const { combiner, ciphertext, publicShares, partialDecryptors } = setup;
    for (const share of partialDecryptors) {
      const publicShare = publicShares.filter((pubShare: any) => pubShare.index == share.index)[0];
      const verified = await combiner.validatePartialDecryptor(ciphertext, publicShare, share);
      expect(verified).toBe(true);
    }
  });
  test('Failure - single invalid', async () => {
    const { combiner, ciphertext, publicShares, invalidDecryptors, invalidIndexes } = setup;
    for (const share of invalidDecryptors) {
      const publicShare = publicShares.filter((pubShare: any) => pubShare.index == share.index)[0];
      if (invalidIndexes.includes(share.index))
        await expect(combiner.validatePartialDecryptor(ciphertext, publicShare, share)).rejects.toThrow(
          'Invalid partial decryptor'
        );
      else expect(
        await combiner.validatePartialDecryptor(ciphertext, publicShare, share)
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
      expect(await decryptor.isEqual(expectedDecryptor)).toBe(qualifiedSet.length >= threshold);
    });
  });
  test('With threshold check', async () => {
    const { combiner, ciphertext, decryptor: expectedDecryptor, partialDecryptors } = setup;
    partialPermutations(partialDecryptors, 0, threshold - 1).forEach(async (qualifiedSet) => {
      await expect(combiner.reconstructDecryptor(qualifiedSet)).rejects.toThrow('Nr shares less than threshold');
    });
    partialPermutations(partialDecryptors, threshold, nrShares).forEach(async (qualifiedSet) => {
      const decryptor = await combiner.reconstructDecryptor(qualifiedSet);
      expect(await decryptor.isEqual(expectedDecryptor)).toBe(true);
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
      expect(await plaintext1.isEqual(message)).toBe(qualifiedSet.length >= threshold);
      expect(await plaintext1.isEqual(plaintext2)).toBe(qualifiedSet.length >= threshold);
    });
  });
  test('With threshold check', async () => {
    const { privateKey, message, ciphertext, partialDecryptors, combiner } = setup;
    partialPermutations(partialDecryptors, 0, threshold - 1).forEach(async (qualifiedSet) => {
      await expect(combiner.decrypt(ciphertext, qualifiedSet)).rejects.toThrow('Nr shares less than threshold');
    });
    partialPermutations(partialDecryptors, threshold, nrShares).forEach(async (qualifiedSet) => {
      const plaintext = await combiner.decrypt(ciphertext, qualifiedSet);
      expect(await plaintext.isEqual(message)).toBe(true);
    });
  });
});
