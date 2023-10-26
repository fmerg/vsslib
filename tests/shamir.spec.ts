const elgamal = require('../src/elgamal');
const shamir = require('../src/shamir');
import { Point } from '../src/elgamal/abstract';
import { Polynomial } from '../src/lagrange';
import { SecretShare, PublicShare, DecryptorShare } from '../src/shamir';
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
    shares.forEach(async (share: any) => {
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

    const publicShares: any[] = [];
    for (const share of shares) {
      const { value: secret, index } = share;
      const value = await ctx.operate(secret, ctx.generator);
      publicShares.push({ value, index });
    }

    // Encrypt something with respect to the combined public key
    const message = await ctx.randomPoint();
    const pub = await ctx.operate(secret, ctx.generator);
    const { ciphertext, decryptor: _decryptor } = await ctx.encrypt(message, pub);

    // Iterate over all combinations of involved parties
    partialPermutations(shares).forEach(async (qualified: any[]) => {
      // Generate decryptor per involved party
      const decryptorShares = [];
      for (const secretShare of qualified) {
        const decryptorShare = await shamir.generateDecryptorShare(ctx, ciphertext, secretShare);
        decryptorShares.push(decryptorShare)
      }
      // Verify decryptors individually
      for (const share of decryptorShares) {
        const pub = shamir.selectShare(share.index, publicShares).value;
        const isValid = await shamir.verifyDecryptorShare(ctx, share, ciphertext, pub);
        expect(isValid).toBe(true);
      }
      // Verify decryptors all together
      const areValid = await shamir.verifyDecryptorShares(
        ctx,
        decryptorShares,
        ciphertext,
        publicShares
      );
      expect(areValid).toBe(true);
      // Reconstruct decryptor from shares
      const decryptor = await shamir.reconstructDecryptor(ctx, decryptorShares);
      // Decryptor correctly retrieved IFF >= t parties are involved
      expect(await decryptor.isEqual(_decryptor)).toBe(qualified.length >= t);
      // Decrypt with decryptor
      const plaintext = await shamir.decrypt(ctx, ciphertext, decryptorShares);
      // Message correctly retrieved IFF >= t parties are involved
      expect(await plaintext.isEqual(message)).toBe(qualified.length >= t);
    });
  });
});
