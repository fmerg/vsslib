import { kem, backend } from '../src';
import { Systems, Algorithms, AesModes } from '../src/enums';
import { cartesian } from './helpers';


const crypto = require('crypto');

const __labels      = Object.values(Systems);
const __aesModes  = [...Object.values(AesModes), undefined];


describe('Encryption and decryption - success', () => {
  it.each(cartesian([__labels, __aesModes]))('over %s/%s', async (label, mode) => {
    const ctx = backend.initGroup(label);

    const { secret, pub } = await ctx.generateKeypair();
    const message = Uint8Array.from(Buffer.from('destroy earth'));

    const { ciphertext } = await kem.encrypt(ctx, message, pub, { mode });
    expect(ciphertext.alpha.mode).toBe(mode == undefined ? AesModes.DEFAULT : mode);

    const plaintext = await kem.decrypt(ctx, ciphertext, secret);
    expect(plaintext).toEqual(message);
  });
});


describe('Encryption and decryption - failure if forged secret', () => {
  it.each(cartesian([__labels, __aesModes]))('over %s/%s', async (label, mode) => {
    const ctx = backend.initGroup(label);

    const { secret, pub } = await ctx.generateKeypair();
    const message = Uint8Array.from(Buffer.from('destroy earth'));

    const { ciphertext } = await kem.encrypt(ctx, message, pub, { mode });
    const forgedSecret = await ctx.randomScalar();
    if (!mode || [AesModes.AES_256_CBC, AesModes.AES_256_GCM].includes(mode)) {
      await expect(kem.decrypt(ctx, ciphertext, forgedSecret)).rejects.toThrow(
        'Could not decrypt: AES decryption failure'
      );
    } else {
      const plaintext = await kem.decrypt(ctx, ciphertext, forgedSecret);
      expect(plaintext).not.toEqual(message);
    }
  });
});


describe('Encryption and decryption - failure if forged iv', () => {
  it.each(cartesian([__labels, __aesModes]))('over %s/%s', async (label, mode) => {
    const ctx = backend.initGroup(label);

    const { secret, pub } = await ctx.generateKeypair();
    const message = Uint8Array.from(Buffer.from('destroy earth'));

    const { ciphertext } = await kem.encrypt(ctx, message, pub, { mode });
    ciphertext.alpha.iv = await crypto.randomBytes(
      mode == AesModes.AES_256_GCM ? 12 : 16
    );
    if (!mode || [AesModes.AES_256_CBC, AesModes.AES_256_GCM].includes(mode)) {
      await expect(kem.decrypt(ctx, ciphertext, secret)).rejects.toThrow(
        'Could not decrypt: AES decryption failure'
      );
    } else {
      const plaintext = await kem.decrypt(ctx, ciphertext, secret);
      expect(plaintext).not.toEqual(message);
    }
  });
});
