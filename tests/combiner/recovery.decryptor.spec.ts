import { recoverDecryptor } from 'vsslib/combiner';
import { cartesian, partialPermutations, isEqualBuffer } from '../utils';
import { mockThresholdDecryptionSetup } from '../helpers';
import { resolveTestConfig } from '../environ';

const { systems, nrShares, threshold, elgamalSchemes: schemes} = resolveTestConfig();


describe('Decryptor recovery', () => {
  it.each(cartesian([systems, schemes])
  )('success - unconditioned - without nonce - over %s/%s', async (system, scheme) => {
    const { ctx, partialPublicKeys, ciphertext, partialDecryptors, decryptor } = await mockThresholdDecryptionSetup({
      scheme, system, nrShares, threshold
    });
    partialPermutations(partialDecryptors).forEach(async (shares) => {
      const { recovered, blame } = await recoverDecryptor(ctx, shares, ciphertext, partialPublicKeys);
      expect(isEqualBuffer(recovered, decryptor)).toBe(shares.length >= threshold);
      expect(blame).toEqual([]);
    });
  });
  it.each(cartesian([systems, schemes])
  )('success - unconditioned - with nonce - over %s/%s', async (system, scheme) => {
    const { ctx, partialPublicKeys, ciphertext, partialDecryptors, decryptor, nonces } = await mockThresholdDecryptionSetup({
      scheme, system, nrShares, threshold, withNonce: true
    });
    partialPermutations(partialDecryptors).forEach(async (shares) => {
      const { recovered, blame } = await recoverDecryptor(
        ctx, shares, ciphertext, partialPublicKeys, { nonces }
      );
      expect(isEqualBuffer(recovered, decryptor)).toBe(shares.length >= threshold);
      expect(blame).toEqual([]);
    });
  });
  it.each(cartesian([systems, schemes])
  )('success - threshold guard - over %s/%s', async (system, scheme) => {
    const { ctx, partialPublicKeys, ciphertext, partialDecryptors, decryptor} = await mockThresholdDecryptionSetup({
      scheme, system, nrShares, threshold
    });
    partialPermutations(partialDecryptors, 0, threshold - 1).forEach(async (shares) => {
      await expect(recoverDecryptor(ctx, shares, ciphertext, partialPublicKeys, { threshold })).rejects.toThrow(
        'Insufficient number of shares'
      );
    });
    partialPermutations(partialDecryptors, threshold, nrShares).forEach(async (shares) => {
      const { recovered, blame } = await recoverDecryptor(ctx, shares, ciphertext, partialPublicKeys);
      expect(isEqualBuffer(recovered, decryptor)).toBe(shares.length >= threshold);
      expect(blame).toEqual([]);
    });
  });
  it.each(cartesian([systems, schemes])
  )('failure - error on invalid - forged proof - over %s/%s', async (system, scheme) => {
    const {
      ctx, partialPublicKeys, ciphertext, partialDecryptors
    } = await mockThresholdDecryptionSetup({
      scheme, system, nrShares, threshold, nrInvalid: 2
    });
    await expect(
      recoverDecryptor(
        ctx, partialDecryptors, ciphertext, partialPublicKeys, { threshold }
      )
    ).rejects.toThrow('Invalid partial decryptor');
  });
  it.each(cartesian([systems, schemes])
  )('failure - error on invalid - forged nonce - over %s/%s', async (system, scheme) => {
    const {
      ctx, partialPublicKeys, ciphertext, partialDecryptors, nonces
    } = await mockThresholdDecryptionSetup({
      scheme, system, nrShares, threshold, nrInvalid: 2, withNonce: true
    });
    await expect(
      recoverDecryptor(
        ctx, partialDecryptors, ciphertext, partialPublicKeys, { threshold, nonces }
      )
    ).rejects.toThrow('Invalid partial decryptor');
  });
  it.each(cartesian([systems, schemes]))
  ('failure - accurate blaming - forged proof - over %s/%s', async (system, scheme) => {
    const {
      ctx, partialPublicKeys, ciphertext, partialDecryptors, decryptor, blame: targetBlame
    } = await mockThresholdDecryptionSetup({
      scheme, system, nrShares, threshold, nrInvalid: 2
    });
    const { recovered, blame } = await recoverDecryptor(
      ctx, partialDecryptors, ciphertext, partialPublicKeys, { errorOnInvalid: false }
    );
    expect(blame.map(b => b.index).sort()).toEqual(targetBlame.sort());
  });
  it.each(cartesian([systems, schemes]))
  ('failure - accurate blaming - forged nonce - over %s/%s', async (system, scheme) => {
    const {
      ctx, partialPublicKeys, ciphertext, partialDecryptors, decryptor, blame: targetBlame, nonces
    } = await mockThresholdDecryptionSetup({
      scheme, system, nrShares, threshold, nrInvalid: 2, withNonce: true
    });
    const { recovered, blame } = await recoverDecryptor(
      ctx, partialDecryptors, ciphertext, partialPublicKeys, { errorOnInvalid: false, nonces }
    );
    expect(isEqualBuffer(recovered, decryptor)).toBe(true);
    expect(blame.map(b => b.index).sort()).toEqual(targetBlame.sort());
  });
  it.each(cartesian([systems, schemes]))(
    'failure - missing public - over %s/%s', async (system, scheme) => {
    const { ctx, partialPublicKeys, ciphertext, partialDecryptors, decryptor } = await mockThresholdDecryptionSetup({
      scheme, system, nrShares, threshold
    });
    await expect(
      recoverDecryptor(
        ctx, partialDecryptors, ciphertext, partialPublicKeys.slice(0, nrShares - 1)
      )
    ).rejects.toThrow('No public share with index')
  });
  it.each(cartesian([systems, schemes]))(
    'failure - missing nonce - over %s/%s', async (system, scheme) => {
    const { ctx, partialPublicKeys, ciphertext, partialDecryptors, decryptor, nonces } = await mockThresholdDecryptionSetup({
      scheme, system, nrShares, threshold, withNonce: true
    });
    await expect(
      recoverDecryptor(
        ctx, partialDecryptors, ciphertext, partialPublicKeys, { nonces: nonces.slice(0, nrShares - 1) }
      )
    ).rejects.toThrow('No nonce for index')
  });
});
