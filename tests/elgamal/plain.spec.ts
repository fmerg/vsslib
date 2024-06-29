import { Systems } from '../../src/enums';
import { leInt2Buff } from '../../src/arith';
import { initBackend } from '../../src/backend';
import { plainElgamal } from '../../src/elgamal/core';

import { cartesian } from '../utils';
import { randomDlogPair } from '../helpers';
import { resolveTestConfig } from '../environ';

const { systems, modes } = resolveTestConfig();


describe('Plain Elgamal encryption', () => {
  it.each(systems)('succes - over %s', async (system) => {
    const ctx = initBackend(system);
    const { x, y } = await randomDlogPair(ctx);
    const message = await ctx.randomPublic();
    const { ciphertext } = await plainElgamal(ctx).encrypt(message, y);
    const plaintext = await plainElgamal(ctx).decrypt(ciphertext, x);
    expect(plaintext).toEqual(message);
  });
  it.each(systems)(
    'failure - forged secret - over %s', async (system) => {
    const ctx = initBackend(system);
    const { x, y } = await randomDlogPair(ctx);
    const message = await ctx.randomPublic();
    const { ciphertext } = await plainElgamal(ctx).encrypt(message, y);
    const forgedSecret = await ctx.randomScalar();
    const plaintext = await plainElgamal(ctx).decrypt(ciphertext, forgedSecret);
    expect(plaintext).not.toEqual(message);
  });
  it.each(systems)('decrypt with decryptor - succes - over %s', async (system) => {
    const ctx = initBackend(system);
    const { x, y } = await randomDlogPair(ctx);
    const message = await ctx.randomPublic();
    const { ciphertext, decryptor } = await plainElgamal(ctx).encrypt(message, y);
    const plaintext = await plainElgamal(ctx).decryptWithDecryptor(
      ciphertext, decryptor
    );
    expect(plaintext).toEqual(message);
  });
  it.each(systems)('decrypt with decryptor - failure - over %s', async (system) => {
    const ctx = initBackend(system);
    const { x, y } = await randomDlogPair(ctx);
    const message = await ctx.randomPublic();
    const { ciphertext, decryptor } = await plainElgamal(ctx).encrypt(message, y);
    const forgedDecryptor = await ctx.randomPublic();
    const plaintext = await plainElgamal(ctx).decryptWithDecryptor(
      ciphertext, forgedDecryptor
    );
    expect(plaintext).not.toEqual(message);
  });
  it.each(systems)('decrypt with randomness - success - over %s', async (system) => {
    const ctx = initBackend(system);
    const { x, y } = await randomDlogPair(ctx);
    const message = await ctx.randomPublic();
    const { ciphertext, randomness } = await plainElgamal(ctx).encrypt(message, y);
    const plaintext = await plainElgamal(ctx).decryptWithRandomness(
      ciphertext, y, randomness
    );
    expect(plaintext).toEqual(message);
  });
  it.each(systems)('decrypt with randomness - failure - forged randomness - over %s', async (system) => {
    const ctx = initBackend(system);
    const { x, y } = await randomDlogPair(ctx);
    const message = await ctx.randomPublic();
    const { ciphertext, randomness } = await plainElgamal(ctx).encrypt(message, y);
    const forgedRandomnes = leInt2Buff(await ctx.randomScalar());
    const plaintext = await plainElgamal(ctx).decryptWithRandomness(
      ciphertext, y, forgedRandomnes
    );
    expect(plaintext).not.toEqual(message);
  });
});
