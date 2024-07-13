import { Systems } from 'vsslib/enums';
import { leInt2Buff } from 'vsslib/arith';
import { initBackend } from 'vsslib/backend';
import { randomSecret, randomPublic } from 'vsslib/secrets';
import { ElgamalSchemes } from 'vsslib/enums';

import elgamal from 'vsslib/elgamal';

import { cartesian } from '../utils';
import { resolveTestConfig } from '../environ';

const { systems, modes } = resolveTestConfig();

const PLAIN = ElgamalSchemes.PLAIN;


describe('Plain Elgamal encryption', () => {
  it.each(systems)('succes - over %s', async (system) => {
    const ctx = initBackend(system);
    const { secret, publicBytes } = await randomSecret(ctx);
    const message = await randomPublic(ctx);
    const { ciphertext } = await elgamal(ctx, PLAIN).encrypt(message, publicBytes);
    const plaintext = await elgamal(ctx, PLAIN).decrypt(ciphertext, secret);
    expect(plaintext).toEqual(message);
  });
  it.each(systems)(
    'failure - forged secret - over %s', async (system) => {
    const ctx = initBackend(system);
    const { secret, publicBytes } = await randomSecret(ctx);
    const message = await randomPublic(ctx);
    const { ciphertext } = await elgamal(ctx, PLAIN).encrypt(message, publicBytes);
    const { secret: forgedSecret } = await randomSecret(ctx);
    const plaintext = await elgamal(ctx, PLAIN).decrypt(ciphertext, forgedSecret);
    expect(plaintext).not.toEqual(message);
  });
  it.each(systems)('decrypt with decryptor - succes - over %s', async (system) => {
    const ctx = initBackend(system);
    const { secret, publicBytes } = await randomSecret(ctx);
    const message = await randomPublic(ctx);
    const { ciphertext, decryptor } = await elgamal(ctx, PLAIN).encrypt(message, publicBytes);
    const plaintext = await elgamal(ctx, PLAIN).decryptWithDecryptor(
      ciphertext, decryptor
    );
    expect(plaintext).toEqual(message);
  });
  it.each(systems)('decrypt with decryptor - failure - over %s', async (system) => {
    const ctx = initBackend(system);
    const { secret, publicBytes } = await randomSecret(ctx);
    const message = await randomPublic(ctx);
    const { ciphertext, decryptor } = await elgamal(ctx, PLAIN).encrypt(message, publicBytes);
    const forgedDecryptor = await randomPublic(ctx);
    const plaintext = await elgamal(ctx, PLAIN).decryptWithDecryptor(
      ciphertext, forgedDecryptor
    );
    expect(plaintext).not.toEqual(message);
  });
  it.each(systems)('decrypt with randomness - success - over %s', async (system) => {
    const ctx = initBackend(system);
    const { secret, publicBytes } = await randomSecret(ctx);
    const message = await randomPublic(ctx);
    const { ciphertext, randomness } = await elgamal(ctx, PLAIN).encrypt(message, publicBytes);
    const plaintext = await elgamal(ctx, PLAIN).decryptWithRandomness(
      ciphertext, publicBytes, randomness
    );
    expect(plaintext).toEqual(message);
  });
  it.each(systems)('decrypt with randomness - failure - forged randomness - over %s', async (system) => {
    const ctx = initBackend(system);
    const { secret, publicBytes } = await randomSecret(ctx);
    const message = await randomPublic(ctx);
    const { ciphertext, randomness } = await elgamal(ctx, PLAIN).encrypt(message, publicBytes);
    const forgedRandomnes = await ctx.generateSecret();
    const plaintext = await elgamal(ctx, PLAIN).decryptWithRandomness(
      ciphertext, publicBytes, forgedRandomnes
    );
    expect(plaintext).not.toEqual(message);
  });
});
