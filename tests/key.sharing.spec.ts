import { key, backend } from '../src';
import { PrivateKey, PublicKey } from '../src/key';
import { Messages } from '../src/key/enums';
import { partialPermutations } from './helpers';


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
  const ctx = backend.initGroup(label);

  // Test reconstruction errors
  await expect(PrivateKey.fromShares([])).rejects.toThrow(Messages.AT_LEAST_ONE_SHARE_NEEDED);
  await expect(PublicKey.fromShares([])).rejects.toThrow(Messages.AT_LEAST_ONE_SHARE_NEEDED);

  // Private key correctly retrieved ONLY IFF >= t parties involved
  partialPermutations(privateShares, 1).forEach(async (qualifiedSet) => {
    const reconstructed = await PrivateKey.fromShares(qualifiedSet);
    expect(await reconstructed.isEqual(privateKey)).toBe(qualifiedSet.length >= t);
  });

  // Public key correctly retrieved ONLY IFF >= t parties involved
  partialPermutations(publicShares, 1).forEach(async (qualifiedSet) => {
    const reconstructed = await PublicKey.fromShares(qualifiedSet);
    expect(await reconstructed.isEqual(publicKey)).toBe(qualifiedSet.length >= t);
  });
});


describe('Key distribution', () => {
  test('Verifiable reconstruction - success', async () => {
  });
  test('Verifiable reconstruction - failure', async () => {
  });
});
