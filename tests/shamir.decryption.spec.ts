import { shamir, elgamal, backend } from '../src';
import { Messages } from '../src/shamir/enums';
import { partialPermutations } from './helpers';


describe('Threshold decryption', () => {
  test('Verifiable decryption - success', async () => {
    const label = 'ed25519';
    const n = 3;
    const t = 2;
    const ctx = backend.initGroup(label);
    const { secret, point: pub } = await ctx.generateKeypair();
    const distribution = await shamir.shareSecret(ctx, secret, n, t);
    const { threshold, secretShares, polynomial, commitments } = distribution;
    const publicShares = await distribution.publicShares();

    // Encrypt something with respect to the combined public key
    const message = await ctx.randomPoint();
    const { ciphertext, decryptor: expectedDecryptor } = await elgamal.encrypt(ctx, message, pub);

    // Iterate over all combinations of involved parties
    partialPermutations(secretShares).forEach(async (qualified: any[]) => {
      // Generate decryptor per involved party
      const partialDecryptors = [];
      for (const secretShare of qualified) {
        const partialDecryptor = await shamir.generatePartialDecryptor(ctx, ciphertext, secretShare);
        partialDecryptors.push(partialDecryptor)
      }
      // Verify decryptors individually
      for (const share of partialDecryptors) {
        const publicShare = shamir.selectShare(share.index, publicShares);
        const verified = await shamir.verifyPartialDecryptor(ctx, ciphertext, publicShare, share);
        expect(verified).toBe(true);
      }
      // Verify decryptors all together
      const [verified, indexes] = await shamir.verifyPartialDecryptors(
        ctx,
        ciphertext,
        publicShares,
        partialDecryptors,
      );
      expect(verified).toBe(true);
      expect(indexes).toEqual([]);

      // Decryptor correctly retrieved IFF >= t parties are involved
      const decryptor = await shamir.reconstructDecryptor(ctx, partialDecryptors);
      expect(await decryptor.isEqual(expectedDecryptor)).toBe(qualified.length >= t);

      // Message correctly retrieved IFF >= t parties are involved
      const plaintext = await shamir.decrypt(ctx, ciphertext, partialDecryptors);
      expect(await plaintext.isEqual(message)).toBe(qualified.length >= t);
      const plaintext2 = await elgamal.decrypt(ctx, ciphertext, { secret })
      expect(await plaintext.isEqual(plaintext2)).toBe(qualified.length >= t);
    });
  });

  test('Verifiable decryption - failure', async () => {
    const label = 'ed25519';
    const n = 5;
    const t = 3;
    const ctx = backend.initGroup(label);
    const { secret, point: pub } = await ctx.generateKeypair();
    const distribution = await shamir.shareSecret(ctx, secret, n, t);
    const { threshold, secretShares, polynomial, commitments } = distribution;
    const publicShares = await distribution.publicShares();

    // Encrypt something with respect to the combined public key
    const message = await ctx.randomPoint();
    const { ciphertext, decryptor: expectedDecryptor } = await elgamal.encrypt(ctx, message, pub);

    // Generate decryptor per involved party
    let partialDecryptors = [];
    const qualified = secretShares.slice(0, t);
    for (const secretShare of qualified) {
      const partialDecryptor = await shamir.generatePartialDecryptor(ctx, ciphertext, secretShare);
      partialDecryptors.push(partialDecryptor)
    }

    // Forge all decryptors besides the first one
    const corruptedIndexes = qualified.slice(1, t).map((share: any) => share.index);
    for (const index of corruptedIndexes) {
      shamir.selectShare(index, partialDecryptors).value = await ctx.randomPoint();
    }

    // Verify decryptors individually
    for (const share of partialDecryptors) {
      const publicShare = shamir.selectShare(share.index, publicShares);
      if (share.index == 1) {
        const verified = await shamir.verifyPartialDecryptor(ctx, ciphertext, publicShare, share);
        expect(verified).toBe(true);
      } else {
        await expect(shamir.verifyPartialDecryptor(ctx, ciphertext, publicShare, share)).rejects.toThrow(
          Messages.INVALID_PARTIAL_DECRYPTOR
        );
      }
    }

    // Verify decryptors all together
    const [verified, detected] = await shamir.verifyPartialDecryptors(
      ctx,
      ciphertext,
      publicShares,
      partialDecryptors,
    );
    expect(verified).toBe(false);
    expect(detected).toEqual(corruptedIndexes);

    // Decryptor is not correctly retrieved
    const decryptor = await shamir.reconstructDecryptor(ctx, partialDecryptors);
    expect(await decryptor.isEqual(expectedDecryptor)).toBe(false);

    // Message is not correctly retrieved
    const plaintext = await shamir.decrypt(ctx, ciphertext, partialDecryptors);
    expect(await plaintext.isEqual(message)).toBe(false);

    // Decryption raises error if share verification enforced
    await expect(
      shamir.decrypt(ctx, ciphertext, partialDecryptors, { publicShares })
    ).rejects.toThrow(Messages.INVALID_PARTIAL_DECRYPTORS_DETECTED);

    // Decryption raises error if less than threshold shares provided
    await expect(
      shamir.decrypt(ctx, ciphertext, partialDecryptors.slice(0, t - 1), { threshold })
    ).rejects.toThrow(Messages.NOT_ENOUGH_SHARES);
  });
});
