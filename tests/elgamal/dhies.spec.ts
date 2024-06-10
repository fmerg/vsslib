import { Algorithms, BlockModes } from '../../src/enums';
import { randomBytes } from '../../src/crypto';
import { leInt2Buff } from '../../src/arith';
import { initGroup } from '../../src/backend';
import { dhiesElgamal } from '../../src/elgamal/core';

import { cartesian } from '../utils';
import { randomDlogPair } from '../helpers';
import { resolveTestConfig } from '../environ';


const { systems, modes, algorithms } = resolveTestConfig();


describe('Decryption - success', () => {
  it.each(cartesian([systems, modes, algorithms]))('over %s/%s/%s', async (
    system, mode, algorithm,
  ) => {
    const ctx = initGroup(system);
    const { x, y } = await randomDlogPair(ctx);
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const { ciphertext } = await dhiesElgamal(ctx, mode, algorithm).encrypt(message, y);
    const plaintext = await dhiesElgamal(ctx, mode, algorithm).decrypt(ciphertext, x);
    expect(plaintext).toEqual(message);
  });
});


describe('Decryption - failure if forged secret', () => {
  it.each(cartesian([systems, modes, algorithms]))('over %s/%s/%s', async (
    system, mode, algorithm,
  ) => {
    const ctx = initGroup(system);
    const { x, y } = await randomDlogPair(ctx);
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const { ciphertext } = await dhiesElgamal(ctx, mode, algorithm).encrypt(message, y);
    const forgedSecret = await ctx.randomScalar();
    await expect(dhiesElgamal(ctx, mode, algorithm).decrypt(ciphertext, forgedSecret)).rejects.toThrow(
      'Could not decrypt: Invalid MAC'
    );
  });
});


describe('Decryption - failure if forged iv', () => {
  it.each(cartesian([systems, modes, algorithms]))('over %s/%s/%s', async (
    system, mode, algorithm
  ) => {
    const ctx = initGroup(system);
    const { x, y } = await randomDlogPair(ctx);
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const { ciphertext } = await dhiesElgamal(ctx, mode, algorithm).encrypt(message, y);
    ciphertext.alpha.iv = await randomBytes(mode == BlockModes.AES_256_GCM ? 12 : 16);
    if (!mode || [BlockModes.AES_256_CBC, BlockModes.AES_256_GCM].includes(mode)) {
      await expect(dhiesElgamal(ctx, mode, algorithm).decrypt(ciphertext, x)).rejects.toThrow(
        'Could not decrypt: AES decryption failure'
      );
    } else {
      const plaintext = await dhiesElgamal(ctx, mode, algorithm).decrypt(ciphertext, x);
      expect(plaintext).not.toEqual(message);
    }
  });
});


describe('Decryption with decryptor - failure if forged decryptor', () => {
  it.each(cartesian([systems, modes]))('over %s/%s', async (system, mode) => {
    const ctx = initGroup(system);
    const { x, y } = await randomDlogPair(ctx);
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const { ciphertext, decryptor } = await dhiesElgamal(ctx, mode, Algorithms.SHA256).encrypt(
      message, y
    );
    const forgedDecryptor = (await ctx.randomPoint()).toBytes();
    await expect(
      dhiesElgamal(ctx, mode, Algorithms.SHA256).decryptWithDecryptor(ciphertext, forgedDecryptor)
    ).rejects.toThrow(
      'Could not decrypt: Invalid MAC'
    );
  });
});


describe('Decryption with randomness - success', () => {
  it.each(cartesian([systems, modes]))('over %s/%s', async (system, mode) => {
    const ctx = initGroup(system);
    const { x, y } = await randomDlogPair(ctx);
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const { ciphertext, randomness } = await dhiesElgamal(ctx, mode, Algorithms.SHA256).encrypt(
      message, y
    );
    const plaintext = await dhiesElgamal(ctx, mode, Algorithms.SHA256).decryptWithRandomness(
      ciphertext, y, randomness
    );
    expect(plaintext).toEqual(message);
  });
});


describe('Decryption with decryptor - failure if forged randomness', () => {
  it.each(cartesian([systems, modes]))('over %s/%s', async (system, mode) => {
    const ctx = initGroup(system);
    const { x, y } = await randomDlogPair(ctx);
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const { ciphertext, randomness } = await dhiesElgamal(ctx, mode, Algorithms.SHA256).encrypt(
      message, y
    );
    const forgedRandomness = leInt2Buff(await ctx.randomScalar());
    await expect(
      dhiesElgamal(ctx, mode, Algorithms.SHA256).decryptWithRandomness(ciphertext, y, forgedRandomness)
    ).rejects.toThrow(
      'Could not decrypt: Invalid MAC'
    );
  });
});
