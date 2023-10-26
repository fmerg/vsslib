const elgamal = require('../src/elgamal');
const shamir = require('../src/shamir');
import { Messages } from '../src/shamir/enums';
import { partialPermutations } from './helpers';


describe('secret sharing', () => {
  test('share with dealer', async () => {
    const label = 'ed25519';
    const ctx = elgamal.initCrypto(label);
    const secret = await ctx.randomScalar();
    const n = 5;
    const t = 3;
    const { threshold, shares, polynomial, commitments } = await shamir.shareSecret(ctx, secret, n, t);

    // Verify computation of each secret share
    shares.forEach(async (share: any) => {
      const isValid = await shamir.verifySecretShare(ctx, share, commitments);
      expect(isValid).toBe(true);
    });

    // Reconstruct secret for each combination of involved parties
    partialPermutations(shares).forEach(async (qualifiedSet) => {
      let reconstructed = shamir.reconstructSecret(qualifiedSet, ctx.order);
      expect(reconstructed == secret).toBe(qualifiedSet.length >= t);
    });
  });

  test('share without dealer', async () => {
  });
});
