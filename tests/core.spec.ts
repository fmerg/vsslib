import { Point } from '../src/backend/abstract'
import { key, backend } from '../src';
import { PrivateKey, PublicKey, PrivateShare, PublicShare } from '../src/key';
import { Messages } from '../src/key/enums';
import { KeyDistribution } from '../src/key';
import { Ciphertext } from '../src/elgamal/core';
import { partialPermutations } from './helpers';
import { Combiner } from '../src/core';

const core = require('../src/core');


describe('Key reconstruction', () => {
  const nrShares = 5;
  const threshold = 3;
  const label = 'ed25519';
  let privateKey: PrivateKey<Point>;
  let publicKey: PublicKey<Point>;
  let distribution: KeyDistribution<Point>;
  let privateShares: PrivateShare<Point>[];
  let publicShares: PublicShare<Point>[];
  let combiner: Combiner<Point>;

  beforeAll(async () => {
    const keypair = await key.generate(label);
    privateKey = keypair.privateKey;
    publicKey = keypair.publicKey;
    distribution = await privateKey.distribute(nrShares, threshold);
    privateShares = await distribution.privateShares;
    publicShares = await distribution.publicShares();
    combiner = core.initCombiner(label);
  });

  test('Private reconstruction - success', async () => {
    partialPermutations(privateShares).forEach(async (qualifiedSet) => {
      const { privateKey: privateReconstructed } = await combiner.reconstructKey(qualifiedSet);
      expect(await privateReconstructed.isEqual(privateKey)).toBe(qualifiedSet.length >= threshold);
    });
  });
  test('Private reconstruction - failure', async () => {
  });
  test('Public reconstruction - success', async () => {
    partialPermutations(publicShares).forEach(async (qualifiedSet) => {
      const publicReconstructed = await combiner.reconstructPublic(qualifiedSet);
      expect(await publicReconstructed.isEqual(publicKey)).toBe(qualifiedSet.length >= threshold);
    });
  });
  test('Public reconstruction - failure', async () => {
  });
});


describe('Decryptor reconstruction', () => {
  const nrShares = 3;
  const threshold = 2;
  const label = 'ed25519';
  let privateKey: PrivateKey<Point>;
  let publicKey: PublicKey<Point>;
  let distribution: KeyDistribution<Point>;
  let privateShares: PrivateShare<Point>[];
  let publicShares: PublicShare<Point>[];
  let message: Point;
  let ciphertext: Ciphertext<Point>;
  let expectedDecryptor: Point;
  let combiner: Combiner<Point>;

  beforeAll(async () => {
    const keypair = await key.generate(label);
    privateKey = keypair.privateKey;
    publicKey = keypair.publicKey;
    distribution = await privateKey.distribute(nrShares, threshold);
    privateShares = await distribution.privateShares;
    publicShares = await distribution.publicShares();
    message = await publicKey.ctx.randomPoint();
    const encryptionOutput = await publicKey.encrypt(message);
    ciphertext = encryptionOutput.ciphertext;
    expectedDecryptor = encryptionOutput.decryptor;
    combiner = core.initCombiner(label);
  });

  test('Success', async () => {
    partialPermutations(privateShares).forEach(async (qualifiedSet: any[]) => {
      // Generate partial decryptors per qualified party
      const shares = [];
      for (const privateShare of qualifiedSet) {
        const share = await privateShare.generatePartialDecryptor(ciphertext);
        shares.push(share);
      }

      // Verify partial decryptors all together
      const [verified, indexes] = await combiner.validatePartialDecryptors(ciphertext, publicShares, shares);
      expect(verified).toBe(true);
      expect(indexes).toEqual([]);

      // Decryptor correctly retrieved IFF >= t parties are involved: TODO
      const decryptor = await combiner.reconstructDecryptor(shares);
      expect(await decryptor.isEqual(expectedDecryptor)).toBe(qualifiedSet.length >= threshold);

      // Message correctly retrieved IFF >= t parties are involved: TODO
      const plaintext = await combiner.decrypt(ciphertext, shares);
      expect(await plaintext.isEqual(message)).toBe(qualifiedSet.length >= threshold);
      const plaintext2 = await privateKey.decrypt(ciphertext);
      expect(await plaintext.isEqual(plaintext2)).toBe(qualifiedSet.length >= threshold);
    });
  });

  test('Failure', async () => {
  });
});


describe('Threshold decryption', () => {
  const nrShares = 3;
  const threshold = 2;
  const label = 'ed25519';
  let privateKey: PrivateKey<Point>;
  let publicKey: PublicKey<Point>;
  let distribution: KeyDistribution<Point>;
  let privateShares: PrivateShare<Point>[];
  let publicShares: PublicShare<Point>[];
  let message: Point;
  let ciphertext: Ciphertext<Point>;
  let expectedDecryptor: Point;
  let combiner: Combiner<Point>;

  beforeAll(async () => {
    const keypair = await key.generate(label);
    privateKey = keypair.privateKey;
    publicKey = keypair.publicKey;
    distribution = await privateKey.distribute(nrShares, threshold);
    privateShares = await distribution.privateShares;
    publicShares = await distribution.publicShares();
    message = await publicKey.ctx.randomPoint();
    const encryptionOutput = await publicKey.encrypt(message);
    ciphertext = encryptionOutput.ciphertext;
    expectedDecryptor = encryptionOutput.decryptor;
    combiner = core.initCombiner(label);
  });

  test('Success', async () => {
    partialPermutations(privateShares).forEach(async (qualifiedSet: any[]) => {
      // Generate partial decryptors per involved party
      const shares = [];
      for (const privateShare of qualifiedSet) {
        const share = await privateShare.generatePartialDecryptor(ciphertext);
        shares.push(share);
      }

      // Verify partial decryptors all together
      const [verified, indexes] = await combiner.validatePartialDecryptors(ciphertext, publicShares, shares);
      expect(verified).toBe(true);
      expect(indexes).toEqual([]);

      // Decryptor correctly retrieved IFF >= t parties are involved: TODO
      const decryptor = await combiner.reconstructDecryptor(shares);
      expect(await decryptor.isEqual(expectedDecryptor)).toBe(qualifiedSet.length >= threshold);

      // Message correctly retrieved IFF >= t parties are involved: TODO
      const plaintext = await combiner.decrypt(ciphertext, shares);
      expect(await plaintext.isEqual(message)).toBe(qualifiedSet.length >= threshold);
      const plaintext2 = await privateKey.decrypt(ciphertext);
      expect(await plaintext.isEqual(plaintext2)).toBe(qualifiedSet.length >= threshold);
    });
  });
  test('Failure', async () => {
  });
});
