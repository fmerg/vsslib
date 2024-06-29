import { Algorithms, BlockModes } from '../../src/enums';
import { leInt2Buff } from '../../src/arith';
import { randomBytes } from '../../src/crypto';
import { initBackend } from '../../src/backend';
import { hybridElgamal } from '../../src/elgamal/core';

import { cartesian } from '../utils';
import { randomDlogPair } from '../helpers';
import { resolveTestConfig } from '../environ';


const { systems, modes } = resolveTestConfig();


describe('Hybrid encryption (Key Encapsulation Mechanism)', () => {
  it.each(cartesian([systems, modes]))(
    'success - over %s/%s', async (system, mode) => {
    const ctx = initBackend(system);
    const { x, y } = await randomDlogPair(ctx);
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const { ciphertext } = await hybridElgamal(ctx, mode).encrypt(message, y);
    const plaintext = await hybridElgamal(ctx, mode).decrypt(ciphertext, x);
    expect(plaintext).toEqual(message);
  });
  it.each(cartesian([systems, modes]))(
    'failure - foged secret - over %s/%s', async (system, mode) => {
    const ctx = initBackend(system);
    const { x, y } = await randomDlogPair(ctx);
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const { ciphertext } = await hybridElgamal(ctx, mode).encrypt(message, y);
    const forgedSecret = await ctx.randomScalar();
    if (!mode || [BlockModes.AES_256_CBC, BlockModes.AES_256_GCM].includes(mode)) {
      await expect(hybridElgamal(ctx, mode).decrypt(ciphertext, forgedSecret)).rejects.toThrow(
        'Could not decrypt: AES decryption failure'
      );
    } else {
      const plaintext = await hybridElgamal(ctx, mode).decrypt(ciphertext, forgedSecret);
      expect(plaintext).not.toEqual(message);
    }
  });
  it.each(cartesian([systems, modes]))(
    'failure - forged IV - over %s/%s', async (system, mode) => {
    const ctx = initBackend(system);
    const { x, y } = await randomDlogPair(ctx);
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const { ciphertext } = await hybridElgamal(ctx, mode).encrypt(message, y);
    ciphertext.alpha.iv = await randomBytes(mode == BlockModes.AES_256_GCM ? 12 : 16)
    if (!mode || [BlockModes.AES_256_CBC, BlockModes.AES_256_GCM].includes(mode)) {
      await expect(hybridElgamal(ctx, mode).decrypt(ciphertext, x)).rejects.toThrow(
        'Could not decrypt: AES decryption failure'
      );
    } else {
      const plaintext = await hybridElgamal(ctx, mode).decrypt(ciphertext, x);
      expect(plaintext).not.toEqual(message);
    }
  });
  it.each(cartesian([systems, modes]))(
    'decrypt with decryptor - success - over %s/%s', async (system, mode) => {
    const ctx = initBackend(system);
    const { x, y } = await randomDlogPair(ctx);
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const { ciphertext, decryptor } = await hybridElgamal(ctx, mode).encrypt(message, y);
    const plaintext = await hybridElgamal(ctx, mode).decryptWithDecryptor(ciphertext, decryptor);
    expect(plaintext).toEqual(message);
  });
  it.each(cartesian([systems, modes]))(
    'decrypt with decryptor - failure - if forged decryptor - over %s/%s', async (system, mode) => {
    const ctx = initBackend(system);
    const { x, y } = await randomDlogPair(ctx);
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const { ciphertext, decryptor } = await hybridElgamal(ctx, mode).encrypt(message, y);
    const forgedDecryptor = await ctx.randomPublic();
    if (!mode || [BlockModes.AES_256_CBC, BlockModes.AES_256_GCM].includes(mode)) {
      await expect(
        hybridElgamal(ctx, mode).decryptWithDecryptor(ciphertext, forgedDecryptor)
      ).rejects.toThrow(
        'Could not decrypt: AES decryption failure'
      );
    } else {
      const plaintext = await hybridElgamal(ctx, mode).decryptWithDecryptor(
        ciphertext, forgedDecryptor
      );
      expect(plaintext).not.toEqual(message);
    }
  });
  it.each(cartesian([systems, modes]))(
    'decrypt with randomness - success - over %s/%s', async (system, mode) => {
    const ctx = initBackend(system);
    const { x, y } = await randomDlogPair(ctx);
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const { ciphertext, randomness } = await hybridElgamal(ctx, mode).encrypt(message, y);
    const plaintext = await hybridElgamal(ctx, mode).decryptWithRandomness(
      ciphertext, y, randomness
    );
    expect(plaintext).toEqual(message);
  });
  it.each(cartesian([systems, modes]))(
    'decrypt with decryptor - failure - forged randomness - over %s/%s', async (system, mode) => {
    const ctx = initBackend(system);
    const { x, y } = await randomDlogPair(ctx);
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const { ciphertext, randomness } = await hybridElgamal(ctx, mode).encrypt(message, y);
    const forgedRandomness = leInt2Buff(await ctx.randomScalar());
    if (!mode || [BlockModes.AES_256_CBC, BlockModes.AES_256_GCM].includes(mode)) {
      await expect(
        hybridElgamal(ctx, mode).decryptWithRandomness(ciphertext, y, forgedRandomness)
      ).rejects.toThrow(
        'Could not decrypt: AES decryption failure'
      );
    } else {
      const plaintext = await hybridElgamal(ctx, mode).decryptWithRandomness(
        ciphertext, y, forgedRandomness
      );
      expect(plaintext).not.toEqual(message);
    }
  });
});
