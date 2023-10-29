const backend = require('../src/backend');
const elgamal = require('../src/elgamal');
const shamir = require('../src/shamir');
import { Messages } from '../src/shamir/enums';
import { partialPermutations } from './helpers';


describe('Threshold encryption', () => {
  test('Verifiable decryption - success', async () => {
    const label = 'ed25519';
    const ctx = backend.initGroup(label);
    const secret = await ctx.randomScalar();
    const n = 3;
    const t = 2;
    const distribution = await shamir.shareSecret(ctx, secret, n, t);
    const { threshold, shares, polynomial, commitments } = distribution;
    const publicShares = await distribution.getPublicShares();

    // Encrypt something with respect to the combined public key
    const message = await ctx.randomPoint();
    const pub = await ctx.operate(secret, ctx.generator);
    const { ciphertext, decryptor: expectedDecryptor } = await elgamal.encrypt(ctx, message, pub);

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
        const verified = await shamir.verifyDecryptorShare(ctx, share, ciphertext, publicShare);
        expect(verified).toBe(true);
      }
      // Verify decryptors all together
      const [verified, indexes] = await shamir.verifyDecryptorShares(
        ctx,
        decryptorShares,
        ciphertext,
        publicShares
      );
      expect(verified).toBe(true);
      expect(indexes).toEqual([]);

      // Decryptor correctly retrieved IFF >= t parties are involved
      const decryptor = await shamir.reconstructDecryptor(ctx, decryptorShares);
      expect(await decryptor.isEqual(expectedDecryptor)).toBe(qualified.length >= t);

      // Message correctly retrieved IFF >= t parties are involved
      const plaintext = await shamir.decrypt(ctx, ciphertext, decryptorShares);
      expect(await plaintext.isEqual(message)).toBe(qualified.length >= t);
      expect(await plaintext.isEqual(await elgamal.decrypt(ctx, ciphertext, { secret }))).toBe(qualified.length >= t);
    });
  });

  test('Verifiable decryption - failure', async () => {
    const label = 'ed25519';
    const ctx = backend.initGroup(label);
    const secret = await ctx.randomScalar();
    const n = 5;
    const t = 3;
    const distribution = await shamir.shareSecret(ctx, secret, n, t);
    const { threshold, shares, polynomial, commitments } = distribution;
    const publicShares = await distribution.getPublicShares();

    // Encrypt something with respect to the combined public key
    const message = await ctx.randomPoint();
    const pub = await ctx.operate(secret, ctx.generator);
    const { ciphertext, decryptor: expectedDecryptor } = await elgamal.encrypt(ctx, message, pub);

    // Generate decryptor per involved party
    let decryptorShares = [];
    const qualified = shares.slice(0, t);
    for (const secretShare of qualified) {
      const decryptorShare = await shamir.generateDecryptorShare(ctx, ciphertext, secretShare);
      decryptorShares.push(decryptorShare)
    }

    // Forge all decryptors besides the first one
    const corruptedIndexes = qualified.slice(1, t).map((share: any) => share.index);
    for (const index of corruptedIndexes) {
      shamir.selectShare(index, decryptorShares).value = await ctx.randomPoint();
    }

    // Verify decryptors individually
    for (const share of decryptorShares) {
      const publicShare = shamir.selectShare(share.index, publicShares);
      if (share.index == 1) {
        const verified = await shamir.verifyDecryptorShare(ctx, share, ciphertext, publicShare);
        expect(verified).toBe(true);
      } else {
        await expect(shamir.verifyDecryptorShare(ctx, share, ciphertext, publicShare)).rejects.toThrow(
          Messages.INVALID_DECRYPTOR_SHARE
        );
      }
    }

    // Verify decryptors all together
    const [verified, detected] = await shamir.verifyDecryptorShares(
      ctx,
      decryptorShares,
      ciphertext,
      publicShares
    );
    expect(verified).toBe(false);
    expect(detected).toEqual(corruptedIndexes);

    // Decryptor is not correctly retrieved
    const decryptor = await shamir.reconstructDecryptor(ctx, decryptorShares);
    expect(await decryptor.isEqual(expectedDecryptor)).toBe(false);

    // Message is not correctly retrieved
    const plaintext = await shamir.decrypt(ctx, ciphertext, decryptorShares);
    expect(await plaintext.isEqual(message)).toBe(false);

    // Decryption raises error if share verification enforced
    await expect(
      shamir.decrypt(ctx, ciphertext, decryptorShares, { publicShares })
    ).rejects.toThrow(Messages.INVALID_DECRYPTOR_SHARES_DETECTED);

    // Decryption raises error if less than threshold shares provided
    await expect(
      shamir.decrypt(ctx, ciphertext, decryptorShares.slice(0, t - 1), { threshold })
    ).rejects.toThrow(Messages.NOT_ENOUGH_SHARES);
  });
});
