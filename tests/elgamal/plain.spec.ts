import { Systems } from '../../src/enums';
import { leInt2Buff } from '../../src/arith';
import { initBackend, generateSecret } from '../../src';
import { ElgamalSchemes } from '../../src/enums';

import elgamal from '../../src/elgamal';

import { cartesian } from '../utils';
import { resolveTestConfig } from '../environ';

const { systems, modes } = resolveTestConfig();

const PLAIN = ElgamalSchemes.PLAIN;


describe('Plain Elgamal encryption', () => {
  it.each(systems)('succes - over %s', async (system) => {
    const ctx = initBackend(system);
    const { secret, publicBytes } = await generateSecret(ctx);
    const message = await ctx.randomPublic();
    const { ciphertext } = await elgamal(ctx, PLAIN).encrypt(message, publicBytes);
    const plaintext = await elgamal(ctx, PLAIN).decrypt(ciphertext, secret);
    expect(plaintext).toEqual(message);
  });
  it.each(systems)(
    'failure - forged secret - over %s', async (system) => {
    const ctx = initBackend(system);
    const { secret, publicBytes } = await generateSecret(ctx);
    const message = await ctx.randomPublic();
    const { ciphertext } = await elgamal(ctx, PLAIN).encrypt(message, publicBytes);
    const { secret: forgedSecret } = await generateSecret(ctx);
    const plaintext = await elgamal(ctx, PLAIN).decrypt(ciphertext, forgedSecret);
    expect(plaintext).not.toEqual(message);
  });
  it.each(systems)('decrypt with decryptor - succes - over %s', async (system) => {
    const ctx = initBackend(system);
    const { secret, publicBytes } = await generateSecret(ctx);
    const message = await ctx.randomPublic();
    const { ciphertext, decryptor } = await elgamal(ctx, PLAIN).encrypt(message, publicBytes);
    const plaintext = await elgamal(ctx, PLAIN).decryptWithDecryptor(
      ciphertext, decryptor
    );
    expect(plaintext).toEqual(message);
  });
  it.each(systems)('decrypt with decryptor - failure - over %s', async (system) => {
    const ctx = initBackend(system);
    const { secret, publicBytes } = await generateSecret(ctx);
    const message = await ctx.randomPublic();
    const { ciphertext, decryptor } = await elgamal(ctx, PLAIN).encrypt(message, publicBytes);
    const forgedDecryptor = await ctx.randomPublic();
    const plaintext = await elgamal(ctx, PLAIN).decryptWithDecryptor(
      ciphertext, forgedDecryptor
    );
    expect(plaintext).not.toEqual(message);
  });
  it.each(systems)('decrypt with randomness - success - over %s', async (system) => {
    const ctx = initBackend(system);
    const { secret, publicBytes } = await generateSecret(ctx);
    const message = await ctx.randomPublic();
    const { ciphertext, randomness } = await elgamal(ctx, PLAIN).encrypt(message, publicBytes);
    const plaintext = await elgamal(ctx, PLAIN).decryptWithRandomness(
      ciphertext, publicBytes, randomness
    );
    expect(plaintext).toEqual(message);
  });
  it.each(systems)('decrypt with randomness - failure - forged randomness - over %s', async (system) => {
    const ctx = initBackend(system);
    const { secret, publicBytes } = await generateSecret(ctx);
    const message = await ctx.randomPublic();
    const { ciphertext, randomness } = await elgamal(ctx, PLAIN).encrypt(message, publicBytes);
    const forgedRandomnes = await ctx.randomSecret();
    const plaintext = await elgamal(ctx, PLAIN).decryptWithRandomness(
      ciphertext, publicBytes, forgedRandomnes
    );
    expect(plaintext).not.toEqual(message);
  });
});
