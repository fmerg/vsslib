import { elgamal, backend } from '../src';
import { Systems } from '../src/enums';
import { cartesian } from './helpers';

const __labels      = Object.values(Systems);


describe('Decryption - success', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const { secret, pub } = await ctx.generateKeypair();
    const message = await ctx.randomPoint();
    const { ciphertext } = await elgamal(ctx).encrypt(message, pub);
    const plaintext = await elgamal(ctx).decrypt(ciphertext, secret);
    expect(await plaintext.isEqual(message)).toBe(true);
  });
});


describe('Decryption - failure if forged secret', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const { secret, pub } = await ctx.generateKeypair();
    const message = await ctx.randomPoint();
    const { ciphertext } = await elgamal(ctx).encrypt(message, pub);
    const forgedSecret = await ctx.randomScalar();
    const plaintext = await elgamal(ctx).decrypt(ciphertext, forgedSecret);
    expect(await plaintext.isEqual(message)).toBe(false);
  });
});


describe('Decryption with decryptor - success', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const { secret, pub } = await ctx.generateKeypair();
    const message = await ctx.randomPoint();
    const { ciphertext, decryptor } = await elgamal(ctx).encrypt(message, pub);
    const plaintext = await elgamal(ctx).decryptWithDecryptor(ciphertext, decryptor);
    expect(await plaintext.isEqual(message)).toBe(true);
  });
});


describe('Decryption with decryptor - failure if forged decryptor', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const { secret, pub } = await ctx.generateKeypair();
    const message = await ctx.randomPoint();
    const { ciphertext, decryptor } = await elgamal(ctx).encrypt(message, pub);
    const forgedDecryptor = await ctx.randomPoint();
    const plaintext = await elgamal(ctx).decryptWithDecryptor(ciphertext, forgedDecryptor);
    expect(await plaintext.isEqual(message)).toBe(false);
  });
});


describe('Decryption with randomness - success', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const { secret, pub } = await ctx.generateKeypair();
    const message = await ctx.randomPoint();
    const { ciphertext, randomness } = await elgamal(ctx).encrypt(message, pub);
    const plaintext = await elgamal(ctx).decryptWithRandomness(ciphertext, pub, randomness);
    expect(await plaintext.isEqual(message)).toBe(true);
  });
});


describe('Decryption with randomness - failure if forged randomness', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const { secret, pub } = await ctx.generateKeypair();
    const message = await ctx.randomPoint();
    const { ciphertext, randomness } = await elgamal(ctx).encrypt(message, pub);
    const forgedRandomnes = await ctx.randomScalar();
    const plaintext = await elgamal(ctx).decryptWithRandomness(ciphertext, pub, forgedRandomnes);
    expect(await plaintext.isEqual(message)).toBe(false);
  });
});
