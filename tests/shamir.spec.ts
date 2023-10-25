const elgamal = require('../src/elgamal');
const shamir = require('../src/shamir');
import { Point } from '../src/elgamal/abstract';
import { Polynomial } from '../src/lagrange';
import { SecretShare, DecryptorShare } from '../src/shamir';
import { mod, modInv } from '../src/utils';
import { partialPermutations } from './helpers';


describe('demo', () => {
  test('demo 1 - sharing with dealer', async () => {
    const label = 'ed25519';
    const ctx = elgamal.initCrypto(label);
    const n = 5;
    const t = 3;
    const {
      nrShares,
      threshold,
      polynomial,
      secret,
      shares,
      commitments,
    } = await shamir.shareSecret(ctx, n, t);
    expect(nrShares).toEqual(n);
    expect(threshold).toEqual(t);
    expect(shares.length).toEqual(n);
    expect(polynomial.degree).toEqual(t - 1);
    expect(commitments.length).toEqual(t);

    // Verify computation of each secret share
    shares.forEach(async (share: SecretShare ) => {
      const isValid = await shamir.verifySecretShare(ctx, share, commitments);
      expect(isValid).toBe(true);
    });

    // Reconstruct secret for each combination of involved parties
    const { order } = ctx;
    partialPermutations(shares).forEach(async (qualifiedSet) => {
      let reconstructed = shamir.reconstructSecret(qualifiedSet, order);
      expect(reconstructed == secret).toBe(qualifiedSet.length >= t);
    });
  });
  test('demo 2 - sharing without dealer', async () => {
  });
  test('demo 3 - threshold decryption', async () => {
    const label = 'ed25519';
    const ctx = elgamal.initCrypto(label);
    const n = 3;
    const t = 2;
    const {
      nrShares,
      threshold,
      polynomial,
      secret,
      shares,
      commitments,
    } = await shamir.shareSecret(ctx, n, t);

    // Encrypt something with respect to the combined public key
    const message = await ctx.randomPoint();
    const pub = await ctx.operate(secret, ctx.generator);
    const { ciphertext, decryptor: _decryptor } = await ctx.encrypt(message, pub);

    // Iterate over all combinations of involved parties
    partialPermutations(shares).forEach(async (qualified: SecretShare[]) => {
      const decryptorShares = [];
      for (const share of qualified) {
        const { index, secret } = share;
        const decryptor = await ctx.operate(secret, ciphertext.beta);
        const proof = await ctx.proveDecryptor(ciphertext, secret, decryptor, { algorithm: 'sha256' });
        decryptorShares.push({
          decryptor,
          index,
          proof,
        });
      }
      // Retrieve decryptor from shares
      const qualifiedIndexes = decryptorShares.map(share => share.index);
      let decryptor = ctx.neutral;
      for (const share of decryptorShares) {
        const { index: i, decryptor: dshare, proof } = share;
        // TODO: Selection by index
        const pubi = await ctx.operate(shares[i - 1].secret, ctx.generator);
        const isValid = await ctx.verifyDecryptor(dshare, ciphertext, pubi, proof);
        expect(isValid).toBe(true);
        // Compute lambdai
        const { order } = ctx;
        const lambdai = shamir.computeLambda(share.index, qualifiedIndexes, order);
        const curr = await ctx.operate(lambdai, dshare);
        decryptor = await ctx.combine(decryptor, curr);
      }
      // Decryptor correctly retrieved IFF >= t parties are involved
      expect(await decryptor.isEqual(_decryptor)).toBe(qualified.length >= t);
      // Decrypt with recryptor
      const plaintext = await ctx.decrypt(ciphertext, { decryptor });
      // Message correctly retrieved IFF >= t parties are involved
      expect(await plaintext.isEqual(message)).toBe(qualified.length >= t);
    });
  });
});
