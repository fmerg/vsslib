import { Algorithms, AesModes } from '../../../src/enums';
import { randomBytes } from '../../../src/crypto/random';
import { kem } from '../../../src/crypto';
import { initGroup } from '../../../src/backend';
import { cartesian } from '../../helpers';
import { resolveTestConfig } from '../../environ';


const { systems, aesModes } = resolveTestConfig();


describe('Decryption - success', () => {
  it.each(cartesian([systems, aesModes]))('over %s/%s', async (system, mode) => {
    const ctx = initGroup(system);
    const { secret, pub } = await ctx.generateKeypair();
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const { ciphertext } = await kem(ctx, mode).encrypt(message, pub);
    const plaintext = await kem(ctx, mode).decrypt(ciphertext, secret);
    expect(plaintext).toEqual(message);
  });
});


describe('Decryption - failure if forged secret', () => {
  it.each(cartesian([systems, aesModes]))('over %s/%s', async (system, mode) => {
    const ctx = initGroup(system);
    const { secret, pub } = await ctx.generateKeypair();
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const { ciphertext } = await kem(ctx, mode).encrypt(message, pub);
    const forgedSecret = await ctx.randomScalar();
    if (!mode || [AesModes.AES_256_CBC, AesModes.AES_256_GCM].includes(mode)) {
      await expect(kem(ctx, mode).decrypt(ciphertext, forgedSecret)).rejects.toThrow(
        'Could not decrypt: AES decryption failure'
      );
    } else {
      const plaintext = await kem(ctx, mode).decrypt(ciphertext, forgedSecret);
      expect(plaintext).not.toEqual(message);
    }
  });
});


describe('Decryption - failure if forged iv', () => {
  it.each(cartesian([systems, aesModes]))('over %s/%s', async (system, mode) => {
    const ctx = initGroup(system);
    const { secret, pub } = await ctx.generateKeypair();
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const { ciphertext } = await kem(ctx, mode).encrypt(message, pub);
    ciphertext.alpha.iv = await randomBytes(mode == AesModes.AES_256_GCM ? 12 : 16)
    if (!mode || [AesModes.AES_256_CBC, AesModes.AES_256_GCM].includes(mode)) {
      await expect(kem(ctx, mode).decrypt(ciphertext, secret)).rejects.toThrow(
        'Could not decrypt: AES decryption failure'
      );
    } else {
      const plaintext = await kem(ctx, mode).decrypt(ciphertext, secret);
      expect(plaintext).not.toEqual(message);
    }
  });
});


describe('Decryption with decryptor - success', () => {
  it.each(cartesian([systems, aesModes]))('over %s/%s', async (system, mode) => {
    const ctx = initGroup(system);
    const { secret, pub } = await ctx.generateKeypair();
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const { ciphertext, decryptor } = await kem(ctx, mode).encrypt(message, pub);
    const plaintext = await kem(ctx, mode).decryptWithDecryptor(ciphertext, decryptor);
    expect(plaintext).toEqual(message);
  });
});


describe('Decryption with decryptor - failure if forged decryptor', () => {
  it.each(cartesian([systems, aesModes]))('over %s/%s', async (system, mode) => {
    const ctx = initGroup(system);
    const { secret, pub } = await ctx.generateKeypair();
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const { ciphertext, decryptor } = await kem(ctx, mode).encrypt(message, pub);
    const forgedDecryptor = await ctx.randomPoint();
    if (!mode || [AesModes.AES_256_CBC, AesModes.AES_256_GCM].includes(mode)) {
      await expect(
        kem(ctx, mode).decryptWithDecryptor(ciphertext, forgedDecryptor)
      ).rejects.toThrow(
        'Could not decrypt: AES decryption failure'
      );
    } else {
      const plaintext = await kem(ctx, mode).decryptWithDecryptor(
        ciphertext, forgedDecryptor
      );
      expect(plaintext).not.toEqual(message);
    }
  });
});


describe('Decryption with randomness - success', () => {
  it.each(cartesian([systems, aesModes]))('over %s/%s', async (system, mode) => {
    const ctx = initGroup(system);
    const { secret, pub } = await ctx.generateKeypair();
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const { ciphertext, randomness } = await kem(ctx, mode).encrypt(message, pub);
    const plaintext = await kem(ctx, mode).decryptWithRandomness(
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
    const { ciphertext, randomness } = await kem(ctx, mode).encrypt(message, pub);
    const forgedRandomnes = await ctx.randomScalar();
    if (!mode || [AesModes.AES_256_CBC, AesModes.AES_256_GCM].includes(mode)) {
      await expect(
        kem(ctx, mode).decryptWithRandomness(ciphertext, pub, forgedRandomnes)
      ).rejects.toThrow(
        'Could not decrypt: AES decryption failure'
      );
    } else {
      const plaintext = await kem(ctx, mode).decryptWithRandomness(
        ciphertext, pub, forgedRandomnes
      );
      expect(plaintext).not.toEqual(message);
    }
  });
});
