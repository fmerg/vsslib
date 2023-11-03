import { Point } from '../src/backend/abstract'
import { key, backend } from '../src';
import { PrivateKey, PublicKey, PublicShare } from '../src/key';
import { Messages } from '../src/key/enums';
import { partialPermutations } from './helpers';
const core = require('../src/core');


export function selectShare<P extends Point>(index: number, shares: PublicShare<P>[]): PublicShare<P> {
  const selected = shares.filter(share => share.index == index)[0];
  if (!selected) throw new Error('No share found for index');
  return selected;
}


test('Key distribution and reconstruction', async () => {
  const label = 'ed25519';
  const { privateKey, publicKey } = await key.generate(label);
  const n = 5;
  const t = 3;
  const distribution = await privateKey.distribute(n, t);
  const { threshold, privateShares, polynomial, commitments } = distribution;
  const publicShares = await distribution.publicShares();
  expect(threshold).toEqual(t);
  expect(privateShares.length).toEqual(n);
  expect(publicShares.length).toEqual(n);
  expect(polynomial.degree).toEqual(t - 1);
  expect(polynomial.evaluate(0)).toEqual(privateKey.scalar);
  expect(commitments.length).toEqual(t);

  // Test reconstruction errors
  await expect(PrivateKey.fromShares([])).rejects.toThrow(Messages.AT_LEAST_ONE_SHARE_NEEDED);
  await expect(PublicKey.fromShares([])).rejects.toThrow(Messages.AT_LEAST_ONE_SHARE_NEEDED);

  // Private key correctly retrieved ONLY IFF >= t parties involved
  const combiner = core.initCombiner(label);
  partialPermutations(privateShares, 1).forEach(async (qualifiedSet) => {
    const reconstructed = await PrivateKey.fromShares(qualifiedSet);
    expect(await reconstructed.isEqual(privateKey)).toBe(qualifiedSet.length >= t);

    const { privateKey: privReconstructed, publicKey: pubReconstructed } = await combiner.reconstructKey(qualifiedSet);
    expect(await privReconstructed.isEqual(privateKey)).toBe(qualifiedSet.length >= t);
    expect(await pubReconstructed.isEqual(publicKey)).toBe(qualifiedSet.length >= t);
  });

  // Public key correctly retrieved ONLY IFF >= t parties involved
  partialPermutations(publicShares, 1).forEach(async (qualifiedSet) => {
    const reconstructed = await PublicKey.fromShares(qualifiedSet);
    expect(await reconstructed.isEqual(publicKey)).toBe(qualifiedSet.length >= t);

    const publicReconstructed = await combiner.reconstructPublic(qualifiedSet);
    expect(await publicReconstructed.isEqual(publicKey)).toBe(qualifiedSet.length >= t);
  });
});


describe('Threshold decryption', () => {
  test('Verifiable decryption - success', async () => {
    const label = 'ed25519';
    const { privateKey, publicKey } = await key.generate(label);
    const n = 3;
    const t = 2;
    const distribution = await privateKey.distribute(n, t);
    const { threshold, privateShares, polynomial, commitments } = distribution;
    const publicShares = await distribution.publicShares();

    const ctx = backend.initGroup(label);
    const message = await ctx.randomPoint();
    const { ciphertext, decryptor: expectedDecryptor } = await publicKey.encrypt(message);

    const combiner = core.initCombiner(label);
    partialPermutations(privateShares, 1).forEach(async (qualifiedSet: any[]) => {
      // Generate partial decryptors per involved party
      const shares = [];
      for (const privateShare of qualifiedSet) {
        const share = await privateShare.generatePartialDecryptor(ciphertext);
        shares.push(share);
      }

      // Verify partial decryptors individually
      for (const share of shares) {
        const publicShare = selectShare(share.index, publicShares);
        const verified = await publicShare.verifyPartialDecryptor(ciphertext, share);
        expect(verified).toBe(true);
      }

      // Verify partial decryptors all together
      const [verified, indexes] = await combiner.validatePartialDecryptors(ciphertext, publicShares, shares);
      expect(verified).toBe(true);
      expect(indexes).toEqual([]);

      // Decryptor correctly retrieved IFF >= t parties are involved: TODO
      const decryptor = await combiner.reconstructDecryptor(shares);
      expect(await decryptor.isEqual(expectedDecryptor)).toBe(qualifiedSet.length >= t);

      // Message correctly retrieved IFF >= t parties are involved: TODO
      const plaintext = await combiner.decrypt(ciphertext, shares);
      expect(await plaintext.isEqual(message)).toBe(qualifiedSet.length >= t);
      const plaintext2 = await privateKey.decrypt(ciphertext);
      expect(await plaintext.isEqual(plaintext2)).toBe(qualifiedSet.length >= t);
    });
  });
  test('Verifiable decryption - failure', async () => {
  });
});
