const elgamal = require('../src/elgamal');
const backend = require('../src/backend');
const shamir = require('../src/shamir');
import { Messages } from '../src/shamir/enums';
import { partialPermutations } from './helpers';


describe('secret sharing', () => {
  test('Share with dealer', async () => {
    const label = 'ed25519';
    const n = 5;
    const t = 3;
    const ctx = backend.initGroup(label);
    const { secret } = await ctx.generateKeypair();
    const { threshold, shares, polynomial, commitments } = await shamir.shareSecret(ctx, secret, n, t);

    shares.forEach(async (share: any) => {
      const verified = await shamir.verifySecretShare(ctx, share, commitments);
      expect(verified).toBe(true);
    });

    partialPermutations(shares).forEach(async (qualifiedSet) => {
      let reconstructed = shamir.reconstructSecret(ctx, qualifiedSet);
      expect(reconstructed == secret).toBe(qualifiedSet.length >= t);
    });
  });

  test('Share without dealer', async () => {
  });
});
