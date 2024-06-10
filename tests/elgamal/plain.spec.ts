import { Systems } from '../../src/enums';
import { leInt2Buff } from '../../src/arith';
import { initGroup } from '../../src/backend';
import { plainElgamal } from '../../src/elgamal/core';

import { cartesian } from '../utils';
import { randomDlogPair } from '../helpers';
import { resolveTestConfig } from '../environ';

const { systems, modes } = resolveTestConfig();


describe('Decryption - success', () => {
  it.each(systems)('over %s', async (system) => {
    const ctx = initGroup(system);
    const { x, y } = await randomDlogPair(ctx);
    const message = (await ctx.randomPoint()).toBytes();
    const { ciphertext } = await plainElgamal(ctx).encrypt(message, y);
    const plaintext = await plainElgamal(ctx).decrypt(ciphertext, x);
    expect(plaintext).toEqual(message);
  });
});


describe('Decryption - failure if forged secret', () => {
  it.each(systems)('over %s', async (system) => {
    const ctx = initGroup(system);
    const { x, y } = await randomDlogPair(ctx);
    const message = (await ctx.randomPoint()).toBytes();
    const { ciphertext } = await plainElgamal(ctx).encrypt(message, y);
    const forgedSecret = await ctx.randomScalar();
    const plaintext = await plainElgamal(ctx).decrypt(ciphertext, forgedSecret);
    expect(plaintext).not.toEqual(message);
  });
});


describe('Decryption with decryptor - success', () => {
  it.each(systems)('over %s', async (system) => {
    const ctx = initGroup(system);
    const { x, y } = await randomDlogPair(ctx);
    const message = (await ctx.randomPoint()).toBytes();
    const { ciphertext, decryptor } = await plainElgamal(ctx).encrypt(message, y);
    const plaintext = await plainElgamal(ctx).decryptWithDecryptor(
      ciphertext, decryptor
    );
    expect(plaintext).toEqual(message);
  });
});


describe('Decryption with decryptor - failure if forged decryptor', () => {
  it.each(systems)('over %s', async (system) => {
    const ctx = initGroup(system);
    const { x, y } = await randomDlogPair(ctx);
    const message = (await ctx.randomPoint()).toBytes();
    const { ciphertext, decryptor } = await plainElgamal(ctx).encrypt(message, y);
    const forgedDecryptor = (await ctx.randomPoint()).toBytes();
    const plaintext = await plainElgamal(ctx).decryptWithDecryptor(
      ciphertext, forgedDecryptor
    );
    expect(plaintext).not.toEqual(message);
  });
});


describe('Decryption with randomness - success', () => {
  it.each(systems)('over %s', async (system) => {
    const ctx = initGroup(system);
    const { x, y } = await randomDlogPair(ctx);
    const message = (await ctx.randomPoint()).toBytes();
    const { ciphertext, randomness } = await plainElgamal(ctx).encrypt(message, y);
    const plaintext = await plainElgamal(ctx).decryptWithRandomness(
      ciphertext, y, randomness
    );
    expect(plaintext).toEqual(message);
  });
});


describe('Decryption with randomness - failure if forged randomness', () => {
  it.each(systems)('over %s', async (system) => {
    const ctx = initGroup(system);
    const { x, y } = await randomDlogPair(ctx);
    const message = (await ctx.randomPoint()).toBytes();
    const { ciphertext, randomness } = await plainElgamal(ctx).encrypt(message, y);
    const forgedRandomnes = leInt2Buff(await ctx.randomScalar());
    const plaintext = await plainElgamal(ctx).decryptWithRandomness(
      ciphertext, y, forgedRandomnes
    );
    expect(plaintext).not.toEqual(message);
  });
});
