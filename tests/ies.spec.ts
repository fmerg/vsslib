import { ies, backend } from '../src';
import { Systems, Algorithms, AesModes } from '../src/enums';
import { cartesian } from './helpers';


const crypto = require('crypto');

const __labels      = Object.values(Systems);
const __aesModes    = [...Object.values(AesModes), undefined];
const __algorithms  = [Algorithms.SHA256, Algorithms.SHA512, undefined];


describe('Encryption and decryption - success', () => {
  it.each(cartesian([__labels, __aesModes, __algorithms]))('over %s/%s/%s', async (
    label, mode, algorithm,
  ) => {
    const ctx = backend.initGroup(label);

    const { secret, point: pub } = await ctx.generateKeypair();
    const message = Uint8Array.from(Buffer.from('destroy earth'));

    const { ciphertext } = await ies.encrypt(ctx, message, pub, { mode, algorithm });
    expect(ciphertext.mode).toBe(mode == undefined ? AesModes.DEFAULT : mode);
    expect(ciphertext.algorithm).toBe(algorithm == undefined ? Algorithms.DEFAULT : algorithm);

    const plaintext = await ies.decrypt(ctx, ciphertext, secret);
    expect(plaintext).toEqual(message);
  });
});


describe('Encryption and decryption - failure if forged secret', () => {
  it.each(cartesian([__labels, __aesModes, __algorithms]))('over %s/%s/%s', async (
    label, mode, algorithm,
  ) => {
    const ctx = backend.initGroup(label);

    const { secret, point: pub } = await ctx.generateKeypair();
    const message = Uint8Array.from(Buffer.from('destroy earth'));

    const { ciphertext } = await ies.encrypt(ctx, message, pub, { mode, algorithm });
    const forgedSecret = await ctx.randomScalar();
    await expect(ies.decrypt(ctx, ciphertext, forgedSecret)).rejects.toThrow(
      'Could not decrypt: Invalid MAC'
    );
  });
});


describe('Encryption and decryption - failure if forged iv', () => {
  it.each(cartesian([__labels, __aesModes]))('over %s/%s', async (label, mode) => {
    const ctx = backend.initGroup(label);

    const { secret, point: pub } = await ctx.generateKeypair();
    const message = Uint8Array.from(Buffer.from('destroy earth'));

    const { ciphertext } = await ies.encrypt(ctx, message, pub, { mode });
    ciphertext.iv = await crypto.randomBytes(mode == AesModes.AES_256_GCM ? 12 : 16);
    if (!mode || [AesModes.AES_256_CBC, AesModes.AES_256_GCM].includes(mode)) {
      await expect(ies.decrypt(ctx, ciphertext, secret)).rejects.toThrow(
        'Could not decrypt: AES decryption failure'
      );
    } else {
      const plaintext = await ies.decrypt(ctx, ciphertext, secret);
      expect(plaintext).not.toEqual(message);
    }
  });
});
