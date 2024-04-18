import { kem, backend } from '../../../src';
import { Systems, Algorithms, AesModes } from '../../../src/enums';
import { cartesian } from '../../helpers';


const crypto = require('crypto');

const __labels      = Object.values(Systems);
const __aesModes  = [...Object.values(AesModes), undefined];


describe('Decryption - success', () => {
  it.each(cartesian([__labels, __aesModes]))('over %s/%s', async (label, mode) => {
    const ctx = backend.initGroup(label);
    const { secret, pub } = await ctx.generateKeypair();
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const { ciphertext } = await kem(ctx, { mode }).encrypt(message, pub);
    expect(ciphertext.alpha.mode).toBe(mode == undefined ? AesModes.DEFAULT : mode);
    const plaintext = await kem(ctx).decrypt(ciphertext, secret);
    expect(plaintext).toEqual(message);
  });
});


describe('Decryption - failure if forged secret', () => {
  it.each(cartesian([__labels, __aesModes]))('over %s/%s', async (label, mode) => {
    const ctx = backend.initGroup(label);
    const { secret, pub } = await ctx.generateKeypair();
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const { ciphertext } = await kem(ctx, { mode }).encrypt(message, pub);
    const forgedSecret = await ctx.randomScalar();
    if (!mode || [AesModes.AES_256_CBC, AesModes.AES_256_GCM].includes(mode)) {
      await expect(kem(ctx).decrypt(ciphertext, forgedSecret)).rejects.toThrow(
        'Could not decrypt: AES decryption failure'
      );
    } else {
      const plaintext = await kem(ctx).decrypt(ciphertext, forgedSecret);
      expect(plaintext).not.toEqual(message);
    }
  });
});


describe('Decryption - failure if forged iv', () => {
  it.each(cartesian([__labels, __aesModes]))('over %s/%s', async (label, mode) => {
    const ctx = backend.initGroup(label);
    const { secret, pub } = await ctx.generateKeypair();
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const { ciphertext } = await kem(ctx, { mode }).encrypt(message, pub);
    ciphertext.alpha.iv = await crypto.randomBytes(
      mode == AesModes.AES_256_GCM ? 12 : 16
    );
    if (!mode || [AesModes.AES_256_CBC, AesModes.AES_256_GCM].includes(mode)) {
      await expect(kem(ctx).decrypt(ciphertext, secret)).rejects.toThrow(
        'Could not decrypt: AES decryption failure'
      );
    } else {
      const plaintext = await kem(ctx).decrypt(ciphertext, secret);
      expect(plaintext).not.toEqual(message);
    }
  });
});


describe('Decryption with decryptor - success', () => {
  it.each(cartesian([__labels, __aesModes]))('over %s/%s', async (label, mode) => {
    const ctx = backend.initGroup(label);
    const { secret, pub } = await ctx.generateKeypair();
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const { ciphertext, decryptor } = await kem(ctx, { mode }).encrypt(message, pub);
    expect(ciphertext.alpha.mode).toBe(mode == undefined ? AesModes.DEFAULT : mode);
    const plaintext = await kem(ctx).decryptWithDecryptor(ciphertext, decryptor);
    expect(plaintext).toEqual(message);
  });
});


describe('Decryption with decryptor - failure if forged decryptor', () => {
  it.each(cartesian([__labels, __aesModes]))('over %s/%s', async (label, mode) => {
    const ctx = backend.initGroup(label);
    const { secret, pub } = await ctx.generateKeypair();
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const { ciphertext, decryptor } = await kem(ctx, { mode }).encrypt(message, pub);
    expect(ciphertext.alpha.mode).toBe(mode == undefined ? AesModes.DEFAULT : mode);
    const forgedDecryptor = await ctx.randomPoint();
    if (!mode || [AesModes.AES_256_CBC, AesModes.AES_256_GCM].includes(mode)) {
      await expect(kem(ctx).decryptWithDecryptor(ciphertext, forgedDecryptor)).rejects.toThrow(
        'Could not decrypt: AES decryption failure'
      );
    } else {
      const plaintext = await kem(ctx).decryptWithDecryptor(ciphertext, forgedDecryptor);
      expect(plaintext).not.toEqual(message);
    }
  });
});


describe('Decryption with randomness - success', () => {
  it.each(cartesian([__labels, __aesModes]))('over %s/%s', async (label, mode) => {
    const ctx = backend.initGroup(label);
    const { secret, pub } = await ctx.generateKeypair();
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const { ciphertext, randomness } = await kem(ctx, { mode }).encrypt(message, pub);
    expect(ciphertext.alpha.mode).toBe(mode == undefined ? AesModes.DEFAULT : mode);
    const plaintext = await kem(ctx).decryptWithRandomness(ciphertext, pub, randomness);
    expect(plaintext).toEqual(message);
  });
});


describe('Decryption with decryptor - failure if forged randomness', () => {
  it.each(cartesian([__labels, __aesModes]))('over %s/%s', async (label, mode) => {
    const ctx = backend.initGroup(label);
    const { secret, pub } = await ctx.generateKeypair();
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const { ciphertext, randomness } = await kem(ctx, { mode }).encrypt(message, pub);
    expect(ciphertext.alpha.mode).toBe(mode == undefined ? AesModes.DEFAULT : mode);
    const forgedRandomnes = await ctx.randomScalar();
    if (!mode || [AesModes.AES_256_CBC, AesModes.AES_256_GCM].includes(mode)) {
      await expect(kem(ctx).decryptWithRandomness(ciphertext, pub, forgedRandomnes)).rejects.toThrow(
        'Could not decrypt: AES decryption failure'
      );
    } else {
      const plaintext = await kem(ctx).decryptWithRandomness(ciphertext, pub, forgedRandomnes);
      expect(plaintext).not.toEqual(message);
    }
  });
});
