import { Systems, Algorithms, AesModes } from '../../../src/schemes';
import { randomBytes } from '../../../src/core/random';
import { ies, backend } from '../../../src';
import { cartesian } from '../../helpers';
import { resolveBackends, resolveAesModes, resolveAlgorithms } from '../../environ';


const __labels      = resolveBackends();
const __aesModes    = resolveAesModes();
const __algorithms  = resolveAlgorithms();


describe('Decryption - success', () => {
  it.each(cartesian([__labels, __aesModes, __algorithms]))('over %s/%s/%s', async (
    label, mode, algorithm,
  ) => {
    const ctx = backend.initGroup(label);
    const { secret, pub } = await ctx.generateKeypair();
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const { ciphertext } = await ies(ctx, mode, algorithm).encrypt(message, pub);
    const plaintext = await ies(ctx, mode, algorithm).decrypt(ciphertext, secret);
    expect(plaintext).toEqual(message);
  });
});


describe('Decryption - failure if forged secret', () => {
  it.each(cartesian([__labels, __aesModes, __algorithms]))('over %s/%s/%s', async (
    label, mode, algorithm,
  ) => {
    const ctx = backend.initGroup(label);
    const { secret, pub } = await ctx.generateKeypair();
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const { ciphertext } = await ies(ctx, mode, algorithm).encrypt(message, pub);
    const forgedSecret = await ctx.randomScalar();
    await expect(ies(ctx, mode, algorithm).decrypt(ciphertext, forgedSecret)).rejects.toThrow(
      'Could not decrypt: Invalid MAC'
    );
  });
});


describe('Decryption - failure if forged iv', () => {
  it.each(cartesian([__labels, __aesModes, __algorithms]))('over %s/%s/%s', async (
    label, mode, algorithm
  ) => {
    const ctx = backend.initGroup(label);
    const { secret, pub } = await ctx.generateKeypair();
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const { ciphertext } = await ies(ctx, mode, algorithm).encrypt(message, pub);
    ciphertext.alpha.iv = await randomBytes(mode == AesModes.AES_256_GCM ? 12 : 16);
    if (!mode || [AesModes.AES_256_CBC, AesModes.AES_256_GCM].includes(mode)) {
      await expect(ies(ctx, mode, algorithm).decrypt(ciphertext, secret)).rejects.toThrow(
        'Could not decrypt: AES decryption failure'
      );
    } else {
      const plaintext = await ies(ctx, mode, algorithm).decrypt(ciphertext, secret);
      expect(plaintext).not.toEqual(message);
    }
  });
});


describe('Decryption with decryptor - failure if forged decryptor', () => {
  it.each(cartesian([__labels, __aesModes]))('over %s/%s', async (label, mode) => {
    const ctx = backend.initGroup(label);
    const { secret, pub } = await ctx.generateKeypair();
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const { ciphertext, decryptor } = await ies(ctx, mode, Algorithms.SHA256).encrypt(message, pub);
    const forgedDecryptor = await ctx.randomPoint();
    await expect(ies(ctx, mode, Algorithms.SHA256).decryptWithDecryptor(ciphertext, forgedDecryptor)).rejects.toThrow(
      'Could not decrypt: Invalid MAC'
    );
  });
});


describe('Decryption with randomness - success', () => {
  it.each(cartesian([__labels, __aesModes]))('over %s/%s', async (label, mode) => {
    const ctx = backend.initGroup(label);
    const { secret, pub } = await ctx.generateKeypair();
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const { ciphertext, randomness } = await ies(ctx, mode, Algorithms.SHA256).encrypt(message, pub);
    const plaintext = await ies(ctx, mode, Algorithms.SHA256).decryptWithRandomness(ciphertext, pub, randomness);
    expect(plaintext).toEqual(message);
  });
});


describe('Decryption with decryptor - failure if forged randomness', () => {
  it.each(cartesian([__labels, __aesModes]))('over %s/%s', async (label, mode) => {
    const ctx = backend.initGroup(label);
    const { secret, pub } = await ctx.generateKeypair();
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const { ciphertext, randomness } = await ies(ctx, mode, Algorithms.SHA256).encrypt(message, pub);
    const forgedRandomnes = await ctx.randomScalar();
    await expect(ies(ctx, mode, Algorithms.SHA256).decryptWithRandomness(ciphertext, pub, forgedRandomnes)).rejects.toThrow(
      'Could not decrypt: Invalid MAC'
    );
  });
});
