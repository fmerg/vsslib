import { Algorithms, AesModes } from '../../src/enums';
import { randomBytes } from '../../src/crypto/random';
import { leInt2Buff } from '../../src/arith';
import { initGroup } from '../../src/backend';
import { iesElgamal } from '../../src/elgamal/ciphers';

import { cartesian } from '../helpers';
import { resolveTestConfig } from '../environ';


const { systems, aesModes, algorithms } = resolveTestConfig();


describe('Decryption - success', () => {
  it.each(cartesian([systems, aesModes, algorithms]))('over %s/%s/%s', async (
    system, mode, algorithm,
  ) => {
    const ctx = initGroup(system);
    const { secret, pub } = await ctx.generateKeypair();
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const { ciphertext } = await iesElgamal(ctx, mode, algorithm).encrypt(message, pub);
    const plaintext = await iesElgamal(ctx, mode, algorithm).decrypt(ciphertext, secret);
    expect(plaintext).toEqual(message);
  });
});


describe('Decryption - failure if forged secret', () => {
  it.each(cartesian([systems, aesModes, algorithms]))('over %s/%s/%s', async (
    system, mode, algorithm,
  ) => {
    const ctx = initGroup(system);
    const { secret, pub } = await ctx.generateKeypair();
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const { ciphertext } = await iesElgamal(ctx, mode, algorithm).encrypt(message, pub);
    const forgedSecret = await ctx.randomScalar();
    await expect(iesElgamal(ctx, mode, algorithm).decrypt(ciphertext, forgedSecret)).rejects.toThrow(
      'Could not decrypt: Invalid MAC'
    );
  });
});


describe('Decryption - failure if forged iv', () => {
  it.each(cartesian([systems, aesModes, algorithms]))('over %s/%s/%s', async (
    system, mode, algorithm
  ) => {
    const ctx = initGroup(system);
    const { secret, pub } = await ctx.generateKeypair();
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const { ciphertext } = await iesElgamal(ctx, mode, algorithm).encrypt(message, pub);
    ciphertext.alpha.iv = await randomBytes(mode == AesModes.AES_256_GCM ? 12 : 16);
    if (!mode || [AesModes.AES_256_CBC, AesModes.AES_256_GCM].includes(mode)) {
      await expect(iesElgamal(ctx, mode, algorithm).decrypt(ciphertext, secret)).rejects.toThrow(
        'Could not decrypt: AES decryption failure'
      );
    } else {
      const plaintext = await iesElgamal(ctx, mode, algorithm).decrypt(ciphertext, secret);
      expect(plaintext).not.toEqual(message);
    }
  });
});


describe('Decryption with decryptor - failure if forged decryptor', () => {
  it.each(cartesian([systems, aesModes]))('over %s/%s', async (system, mode) => {
    const ctx = initGroup(system);
    const { secret, pub } = await ctx.generateKeypair();
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const { ciphertext, decryptor } = await iesElgamal(ctx, mode, Algorithms.SHA256).encrypt(
      message, pub
    );
    const forgedDecryptor = (await ctx.randomPoint()).toBytes();
    await expect(
      iesElgamal(ctx, mode, Algorithms.SHA256).decryptWithDecryptor(ciphertext, forgedDecryptor)
    ).rejects.toThrow(
      'Could not decrypt: Invalid MAC'
    );
  });
});


describe('Decryption with randomness - success', () => {
  it.each(cartesian([systems, aesModes]))('over %s/%s', async (system, mode) => {
    const ctx = initGroup(system);
    const { secret, pub } = await ctx.generateKeypair();
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const { ciphertext, randomness } = await iesElgamal(ctx, mode, Algorithms.SHA256).encrypt(
      message, pub
    );
    const plaintext = await iesElgamal(ctx, mode, Algorithms.SHA256).decryptWithRandomness(
      ciphertext, pub, randomness
    );
    expect(plaintext).toEqual(message);
  });
});


describe('Decryption with decryptor - failure if forged randomness', () => {
  it.each(cartesian([systems, aesModes]))('over %s/%s', async (system, mode) => {
    const ctx = initGroup(system);
    const { secret, pub } = await ctx.generateKeypair();
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const { ciphertext, randomness } = await iesElgamal(ctx, mode, Algorithms.SHA256).encrypt(
      message, pub
    );
    const forgedRandomnes = leInt2Buff(await ctx.randomScalar());
    await expect(
      iesElgamal(ctx, mode, Algorithms.SHA256).decryptWithRandomness(ciphertext, pub, forgedRandomnes)
    ).rejects.toThrow(
      'Could not decrypt: Invalid MAC'
    );
  });
});
