import { Algorithms, AesModes } from '../../src/enums';
import { leInt2Buff } from '../../src/arith';
import { randomBytes } from '../../src/crypto';
import { initGroup } from '../../src/backend';
import { hybridElgamal } from '../../src/elgamal/core';

import { cartesian } from '../utils';
import { resolveTestConfig } from '../environ';


const { systems, aesModes } = resolveTestConfig();


describe('Decryption - success', () => {
  it.each(cartesian([systems, aesModes]))('over %s/%s', async (system, mode) => {
    const ctx = initGroup(system);
    const { secret, publicPoint: y } = await ctx.generateSecret();
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const { ciphertext } = await hybridElgamal(ctx, mode).encrypt(message, y);
    const plaintext = await hybridElgamal(ctx, mode).decrypt(ciphertext, secret);
    expect(plaintext).toEqual(message);
  });
});


describe('Decryption - failure if forged secret', () => {
  it.each(cartesian([systems, aesModes]))('over %s/%s', async (system, mode) => {
    const ctx = initGroup(system);
    const { secret, publicPoint: y } = await ctx.generateSecret();
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const { ciphertext } = await hybridElgamal(ctx, mode).encrypt(message, y);
    const forgedSecret = await ctx.randomScalar();
    if (!mode || [AesModes.AES_256_CBC, AesModes.AES_256_GCM].includes(mode)) {
      await expect(hybridElgamal(ctx, mode).decrypt(ciphertext, forgedSecret)).rejects.toThrow(
        'Could not decrypt: AES decryption failure'
      );
    } else {
      const plaintext = await hybridElgamal(ctx, mode).decrypt(ciphertext, forgedSecret);
      expect(plaintext).not.toEqual(message);
    }
  });
});


describe('Decryption - failure if forged iv', () => {
  it.each(cartesian([systems, aesModes]))('over %s/%s', async (system, mode) => {
    const ctx = initGroup(system);
    const { secret, publicPoint: y } = await ctx.generateSecret();
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const { ciphertext } = await hybridElgamal(ctx, mode).encrypt(message, y);
    ciphertext.alpha.iv = await randomBytes(mode == AesModes.AES_256_GCM ? 12 : 16)
    if (!mode || [AesModes.AES_256_CBC, AesModes.AES_256_GCM].includes(mode)) {
      await expect(hybridElgamal(ctx, mode).decrypt(ciphertext, secret)).rejects.toThrow(
        'Could not decrypt: AES decryption failure'
      );
    } else {
      const plaintext = await hybridElgamal(ctx, mode).decrypt(ciphertext, secret);
      expect(plaintext).not.toEqual(message);
    }
  });
});


describe('Decryption with decryptor - success', () => {
  it.each(cartesian([systems, aesModes]))('over %s/%s', async (system, mode) => {
    const ctx = initGroup(system);
    const { secret, publicPoint: y } = await ctx.generateSecret();
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const { ciphertext, decryptor } = await hybridElgamal(ctx, mode).encrypt(message, y);
    const plaintext = await hybridElgamal(ctx, mode).decryptWithDecryptor(ciphertext, decryptor);
    expect(plaintext).toEqual(message);
  });
});


describe('Decryption with decryptor - failure if forged decryptor', () => {
  it.each(cartesian([systems, aesModes]))('over %s/%s', async (system, mode) => {
    const ctx = initGroup(system);
    const { secret, publicPoint: y } = await ctx.generateSecret();
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const { ciphertext, decryptor } = await hybridElgamal(ctx, mode).encrypt(message, y);
    const forgedDecryptor = (await ctx.randomPoint()).toBytes();
    if (!mode || [AesModes.AES_256_CBC, AesModes.AES_256_GCM].includes(mode)) {
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
});


describe('Decryption with randomness - success', () => {
  it.each(cartesian([systems, aesModes]))('over %s/%s', async (system, mode) => {
    const ctx = initGroup(system);
    const { secret, publicPoint: y } = await ctx.generateSecret();
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const { ciphertext, randomness } = await hybridElgamal(ctx, mode).encrypt(message, y);
    const plaintext = await hybridElgamal(ctx, mode).decryptWithRandomness(
      ciphertext, y, randomness
    );
    expect(plaintext).toEqual(message);
  });
});


describe('Decryption with decryptor - failure if forged randomness', () => {
  it.each(cartesian([systems, aesModes]))('over %s/%s', async (system, mode) => {
    const ctx = initGroup(system);
    const { secret, publicPoint: y } = await ctx.generateSecret();
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const { ciphertext, randomness } = await hybridElgamal(ctx, mode).encrypt(message, y);
    const forgedRandomness = leInt2Buff(await ctx.randomScalar());
    if (!mode || [AesModes.AES_256_CBC, AesModes.AES_256_GCM].includes(mode)) {
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
