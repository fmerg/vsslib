import { shamir, backend } from '../src';
import { Messages } from '../src/shamir/enums';
import { partialPermutations } from './helpers';


test('Secret sharing', async () => {
  const label = 'ed25519';
  const ctx = backend.initGroup(label);
  const { secret, point: pub } = await ctx.generateKeypair();

  const n = 5;
  const t = 3;
  const distribution = await shamir.shareSecret(ctx, secret, n, t);
  const { threshold, secretShares, polynomial, commitments } = distribution;
  const publicShares = await distribution.publicShares();

  secretShares.forEach(async (share: any) => {
    const verified = await shamir.verifySecretShare(ctx, share, commitments);
    expect(verified).toBe(true);
  });

  partialPermutations(secretShares).forEach(async (qualifiedSet) => {
    let reconstructed = shamir.reconstructSecret(ctx, qualifiedSet);
    expect(reconstructed == secret).toBe(qualifiedSet.length >= t);
  });

  partialPermutations(publicShares).forEach(async (qualifiedSet) => {
    let reconstructed = await shamir.reconstructPublic(ctx, qualifiedSet);
    expect(await reconstructed.isEqual(pub)).toBe(qualifiedSet.length >= t);
  });
});
