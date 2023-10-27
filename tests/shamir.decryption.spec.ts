const elgamal = require('../src/elgamal');
const shamir = require('../src/shamir');
import { Messages } from '../src/shamir/enums';
import { partialPermutations } from './helpers';


describe('demo', () => {
  test('Threshold decryption - success', async () => {
    const label = 'ed25519';
    const ctx = elgamal.initCrypto(label);
    const secret = await ctx.randomScalar();
    const n = 3;
    const t = 2;
    const distribution = await shamir.shareSecret(ctx, secret, n, t);
    const { threshold, shares, polynomial, commitments } = distribution;
    const publicShares = await distribution.getPublicShares();

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
        const publicShare = shamir.selectShare(share.index, publicShares);
        const isValid = await shamir.verifyDecryptorShare(ctx, share, ciphertext, publicShare);
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

      // Decryptor correctly retrieved IFF >= t parties are involved
      const decryptor = await shamir.reconstructDecryptor(ctx, decryptorShares);
      expect(await decryptor.isEqual(_decryptor)).toBe(qualified.length >= t);

      // Message correctly retrieved IFF >= t parties are involved
      const plaintext = await shamir.decrypt(ctx, ciphertext, decryptorShares);
      expect(await plaintext.isEqual(message)).toBe(qualified.length >= t);
      expect(await plaintext.isEqual(await ctx.decrypt(ciphertext, { secret }))).toBe(qualified.length >= t);
    });
  });
});
