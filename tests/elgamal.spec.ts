import { elgamal, backend, utils } from '../src';
import { Systems, Algorithms } from '../src/enums';
import { Algorithm } from '../src/types';
import { cartesian } from './helpers';


const __labels      = Object.values(Systems);
const __algorithms  = [...Object.values(Algorithms), undefined];


describe('Decryption - success', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const { secret, pub } = await ctx.generateKeypair();
    const message = await ctx.randomPoint();
    const { ciphertext } = await elgamal.encrypt(ctx, message, pub);
    const plaintext = await elgamal.decrypt(ctx, ciphertext, secret);
    expect(await plaintext.isEqual(message)).toBe(true);
  });
});


describe('Decryption - failure if forged secret', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const { secret, pub } = await ctx.generateKeypair();
    const message = await ctx.randomPoint();
    const { ciphertext } = await elgamal.encrypt(ctx, message, pub);
    const forgedSecret = await ctx.randomScalar();
    const plaintext = await elgamal.decrypt(ctx, ciphertext, forgedSecret);
    expect(await plaintext.isEqual(message)).toBe(false);
  });
});


describe('Decryption with decryptor - success', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const { secret, pub } = await ctx.generateKeypair();
    const message = await ctx.randomPoint();
    const { ciphertext, decryptor } = await elgamal.encrypt(ctx, message, pub);
    const plaintext = await elgamal.decryptWithDecryptor(ctx, ciphertext, decryptor);
    expect(await plaintext.isEqual(message)).toBe(true);
  });
});


describe('Decryption with decryptor - failure if forged decryptor', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const { secret, pub } = await ctx.generateKeypair();
    const message = await ctx.randomPoint();
    const { ciphertext, decryptor } = await elgamal.encrypt(ctx, message, pub);
    const forgedDecryptor = await ctx.randomPoint();
    const plaintext = await elgamal.decryptWithDecryptor(ctx, ciphertext, forgedDecryptor);
    expect(await plaintext.isEqual(message)).toBe(false);
  });
});


describe('Decryption with randomness - success', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const { secret, pub } = await ctx.generateKeypair();
    const message = await ctx.randomPoint();
    const { ciphertext, randomness } = await elgamal.encrypt(ctx, message, pub);
    const plaintext = await elgamal.decryptWithRandomness(ctx, ciphertext, pub, randomness);
    expect(await plaintext.isEqual(message)).toBe(true);
  });
});


describe('Decryption with randomness - failure if forged randomness', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const { secret, pub } = await ctx.generateKeypair();
    const message = await ctx.randomPoint();
    const { ciphertext, randomness } = await elgamal.encrypt(ctx, message, pub);
    const forgedRandomnes = await ctx.randomScalar();
    const plaintext = await elgamal.decryptWithRandomness(ctx, ciphertext, pub, forgedRandomnes);
    expect(await plaintext.isEqual(message)).toBe(false);
  });
});
