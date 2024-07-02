import { Algorithms, BlockModes } from '../../src/enums';
import { leInt2Buff } from '../../src/arith';
import { randomBytes } from '../../src/crypto';
import { initBackend, generateSecret } from '../../src';
import { HybridCiphertext } from '../../src/elgamal/driver';
import { ElgamalSchemes } from '../../src/enums';

import elgamal from '../../src/elgamal';

import { cartesian } from '../utils';
import { buildMessage } from '../helpers';
import { resolveTestConfig } from '../environ';


const { systems, modes } = resolveTestConfig();

const HYBRID = ElgamalSchemes.HYBRID;


describe('Hybrid encryption (Key Encapsulation Mechanism)', () => {
  it.each(cartesian([systems, modes]))(
    'success - over %s/%s', async (system, mode) => {
    const ctx = initBackend(system);
    const { secret, publicBytes } = await generateSecret(ctx);
    const message = await buildMessage(ctx, HYBRID);
    const { ciphertext } = await elgamal(ctx, HYBRID, undefined, mode).encrypt(message, publicBytes);
    const plaintext = await elgamal(ctx, HYBRID, undefined, mode).decrypt(ciphertext, secret);
    expect(plaintext).toEqual(message);
  });
  it.each(cartesian([systems, modes]))(
    'failure - foged secret - over %s/%s', async (system, mode) => {
    const ctx = initBackend(system);
    const { secret, publicBytes } = await generateSecret(ctx);
    const message = await buildMessage(ctx, HYBRID);
    const { ciphertext } = await elgamal(ctx, HYBRID, undefined, mode).encrypt(message, publicBytes);
    const { secret: forgedSecret } = await generateSecret(ctx);
    if (!mode || [BlockModes.AES_256_CBC, BlockModes.AES_256_GCM].includes(mode)) {
      await expect(elgamal(ctx, HYBRID, undefined, mode).decrypt(ciphertext, forgedSecret)).rejects.toThrow(
        'Could not decrypt: AES decryption failure'
      );
    } else {
      const plaintext = await elgamal(ctx, HYBRID, undefined, mode).decrypt(ciphertext, forgedSecret);
      expect(plaintext).not.toEqual(message);
    }
  });
  it.each(cartesian([systems, modes]))(
    'failure - forged IV - over %s/%s', async (system, mode) => {
    const ctx = initBackend(system);
    const { secret, publicBytes } = await generateSecret(ctx);
    const message = await buildMessage(ctx, HYBRID);
    const { ciphertext } = await elgamal(ctx, HYBRID, undefined, mode).encrypt(message, publicBytes);
    (ciphertext as HybridCiphertext).alpha.iv = await randomBytes(mode == BlockModes.AES_256_GCM ? 12 : 16)
    if (!mode || [BlockModes.AES_256_CBC, BlockModes.AES_256_GCM].includes(mode)) {
      await expect(elgamal(ctx, HYBRID, undefined, mode).decrypt(ciphertext, secret)).rejects.toThrow(
        'Could not decrypt: AES decryption failure'
      );
    } else {
      const plaintext = await elgamal(ctx, HYBRID, undefined, mode).decrypt(ciphertext, secret);
      expect(plaintext).not.toEqual(message);
    }
  });
  it.each(cartesian([systems, modes]))(
    'decrypt with decryptor - success - over %s/%s', async (system, mode) => {
    const ctx = initBackend(system);
    const { secret, publicBytes } = await generateSecret(ctx);
    const message = await buildMessage(ctx, HYBRID);
    const { ciphertext, decryptor } = await elgamal(ctx, HYBRID, undefined, mode).encrypt(message, publicBytes);
    const plaintext = await elgamal(ctx, HYBRID, undefined ,mode).decryptWithDecryptor(ciphertext, decryptor);
    expect(plaintext).toEqual(message);
  });
  it.each(cartesian([systems, modes]))(
    'decrypt with decryptor - failure - if forged decryptor - over %s/%s', async (system, mode) => {
    const ctx = initBackend(system);
    const { secret, publicBytes } = await generateSecret(ctx);
    const message = await buildMessage(ctx, HYBRID);
    const { ciphertext, decryptor } = await elgamal(ctx, HYBRID, undefined, mode).encrypt(message, publicBytes);
    const forgedDecryptor = await ctx.randomPublic();
    if (!mode || [BlockModes.AES_256_CBC, BlockModes.AES_256_GCM].includes(mode)) {
      await expect(
        elgamal(ctx, HYBRID, undefined, mode).decryptWithDecryptor(ciphertext, forgedDecryptor)
      ).rejects.toThrow(
        'Could not decrypt: AES decryption failure'
      );
    } else {
      const plaintext = await elgamal(ctx, HYBRID, undefined, mode).decryptWithDecryptor(
        ciphertext, forgedDecryptor
      );
      expect(plaintext).not.toEqual(message);
    }
  });
  it.each(cartesian([systems, modes]))(
    'decrypt with randomness - success - over %s/%s', async (system, mode) => {
    const ctx = initBackend(system);
    const { secret, publicBytes } = await generateSecret(ctx);
    const message = await buildMessage(ctx, HYBRID);
    const { ciphertext, randomness } = await elgamal(ctx, HYBRID, undefined, mode).encrypt(message, publicBytes);
    const plaintext = await elgamal(ctx, HYBRID, undefined, mode).decryptWithRandomness(
      ciphertext, publicBytes, randomness
    );
    expect(plaintext).toEqual(message);
  });
  it.each(cartesian([systems, modes]))(
    'decrypt with decryptor - failure - forged randomness - over %s/%s', async (system, mode) => {
    const ctx = initBackend(system);
    const { secret, publicBytes } = await generateSecret(ctx);
    const message = await buildMessage(ctx, HYBRID);
    const { ciphertext, randomness } = await elgamal(ctx, HYBRID, undefined, mode).encrypt(message, publicBytes)
    const forgedRandomness = await ctx.randomSecret();
    if (!mode || [BlockModes.AES_256_CBC, BlockModes.AES_256_GCM].includes(mode)) {
      await expect(
        elgamal(ctx, HYBRID, undefined, mode).decryptWithRandomness(ciphertext, publicBytes, forgedRandomness)
      ).rejects.toThrow(
        'Could not decrypt: AES decryption failure'
      );
    } else {
      const plaintext = await elgamal(ctx, HYBRID, undefined, mode).decryptWithRandomness(
        ciphertext, publicBytes, forgedRandomness
      );
      expect(plaintext).not.toEqual(message);
    }
  });
});
