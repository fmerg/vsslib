import { recoverDecryptor } from 'vsslib/combiner';
import { cartesian, partialPermutations, isEqualBuffer } from '../utils';
import { createThresholdDecryptionSetup } from '../helpers';
import { resolveTestConfig } from '../environ';

const { systems, nrShares, threshold, elgamalSchemes: schemes} = resolveTestConfig();


describe('Decryptor recovery', () => {
  it.each(cartesian([systems, schemes])
  )('success - unconditioned - without nonce - over %s/%s', async (system, scheme) => {
    const { ctx, publicShares, ciphertext, partialDecryptors, decryptor } = await createThresholdDecryptionSetup({
      scheme, system, nrShares, threshold
    });
    partialPermutations(partialDecryptors).forEach(async (qualifiedShares) => {
      const { recovered, blame } = await recoverDecryptor(ctx, qualifiedShares, ciphertext, publicShares);
      expect(isEqualBuffer(recovered, decryptor)).toBe(qualifiedShares.length >= threshold);
      expect(blame).toEqual([]);
    });
  });
  it.each(cartesian([systems, schemes])
  )('success - unconditioned - with nonce - over %s/%s', async (system, scheme) => {
    const { ctx, publicShares, ciphertext, partialDecryptors, decryptor, nonces } = await createThresholdDecryptionSetup({
      scheme, system, nrShares, threshold, withNonce: true
    });
    partialPermutations(partialDecryptors).forEach(async (qualifiedShares) => {
      const { recovered, blame } = await recoverDecryptor(
        ctx, qualifiedShares, ciphertext, publicShares, { nonces }
      );
      expect(isEqualBuffer(recovered, decryptor)).toBe(qualifiedShares.length >= threshold);
      expect(blame).toEqual([]);
    });
  });
  it.each(cartesian([systems, schemes])
  )('success - threshold guard - over %s/%s', async (system, scheme) => {
    const { ctx, publicShares, ciphertext, partialDecryptors, decryptor} = await createThresholdDecryptionSetup({
      scheme, system, nrShares, threshold
    });
    partialPermutations(partialDecryptors, 0, threshold - 1).forEach(async (qualifiedShares) => {
      await expect(recoverDecryptor(ctx, qualifiedShares, ciphertext, publicShares, { threshold })).rejects.toThrow(
        'Insufficient number of shares'
      );
    });
    partialPermutations(partialDecryptors, threshold, nrShares).forEach(async (qualifiedShares) => {
      const { recovered, blame } = await recoverDecryptor(ctx, qualifiedShares, ciphertext, publicShares);
      expect(isEqualBuffer(recovered, decryptor)).toBe(qualifiedShares.length >= threshold);
      expect(blame).toEqual([]);
    });
  });
  it.each(cartesian([systems, schemes])
  )('failure - error on invalid - forged proof - over %s/%s', async (system, scheme) => {
    const {
      ctx, publicShares, ciphertext, partialDecryptors, invalidDecryptors
    } = await createThresholdDecryptionSetup({
      scheme, system, nrShares, threshold, nrInvalid: 2
    });
    await expect(
      recoverDecryptor(
        ctx, invalidDecryptors, ciphertext, publicShares, { threshold }
      )
    ).rejects.toThrow('Invalid partial decryptor');
  });
  it.each(cartesian([systems, schemes])
  )('failure - error on invalid - forged nonce - over %s/%s', async (system, scheme) => {
    const {
      ctx, publicShares, ciphertext, partialDecryptors, invalidDecryptors, nonces
    } = await createThresholdDecryptionSetup({
      scheme, system, nrShares, threshold, nrInvalid: 2, withNonce: true
    });
    await expect(
      recoverDecryptor(
        ctx, invalidDecryptors, ciphertext, publicShares, { threshold, nonces }
      )
    ).rejects.toThrow('Invalid partial decryptor');
  });
  it.each(cartesian([systems, schemes]))
  ('failure - accurate blaming - forged proof - over %s/%s', async (system, scheme) => {
    const {
      ctx, publicShares, ciphertext, partialDecryptors, invalidDecryptors, decryptor, blame: targetBlame
    } = await createThresholdDecryptionSetup({
      scheme, system, nrShares, threshold, nrInvalid: 2
    });
    const { recovered, blame } = await recoverDecryptor(
      ctx, invalidDecryptors, ciphertext, publicShares, { errorOnInvalid: false }
    );
    expect(blame.sort()).toEqual(targetBlame.sort());
  });
  it.each(cartesian([systems, schemes]))
  ('failure - accurate blaming - forged nonce - over %s/%s', async (system, scheme) => {
    const {
      ctx, publicShares, ciphertext, partialDecryptors, invalidDecryptors, decryptor, blame: targetBlame, nonces
    } = await createThresholdDecryptionSetup({
      scheme, system, nrShares, threshold, nrInvalid: 2, withNonce: true
    });
    const { recovered, blame } = await recoverDecryptor(
      ctx, invalidDecryptors, ciphertext, publicShares, { errorOnInvalid: false, nonces }
    );
    expect(isEqualBuffer(recovered, decryptor)).toBe(true);
    expect(blame.sort()).toEqual(targetBlame.sort());
  });
  it.each(cartesian([systems, schemes]))(
    'failure - missing public - over %s/%s', async (system, scheme) => {
    const { ctx, publicShares, ciphertext, partialDecryptors, decryptor } = await createThresholdDecryptionSetup({
      scheme, system, nrShares, threshold
    });
    await expect(
      recoverDecryptor(
        ctx, partialDecryptors, ciphertext, publicShares.slice(0, nrShares - 1)
      )
    ).rejects.toThrow('No public share with index')
  });
  it.each(cartesian([systems, schemes]))(
    'failure - missing nonce - over %s/%s', async (system, scheme) => {
    const { ctx, publicShares, ciphertext, partialDecryptors, decryptor, nonces } = await createThresholdDecryptionSetup({
      scheme, system, nrShares, threshold, withNonce: true
    });
    await expect(
      recoverDecryptor(
        ctx, partialDecryptors, ciphertext, publicShares, { nonces: nonces.slice(0, nrShares - 1) }
      )
    ).rejects.toThrow('No nonce for index')
  });
});
