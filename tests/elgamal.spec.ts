import { elgamal, backend, utils } from '../src';
import { Systems, Algorithms } from '../src/enums';
import { Algorithm } from '../src/types';
import { cartesian } from './helpers';


const __labels      = Object.values(Systems);
const __algorithms  = [...Object.values(Algorithms), undefined];


describe('encryption - decryption with secret key failure', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);

    const { secret, point: pub } = await ctx.generateKeypair();

    const message = await ctx.randomPoint();
    const { ciphertext, randomness, decryptor } = await elgamal.encrypt(ctx, message, pub);

    const forged = await ctx.randomScalar();
    const plaintext = await elgamal.decrypt(ctx, ciphertext, { secret: forged });
    expect(await plaintext.isEqual(message)).toBe(false);
  });
});


describe('encryption - decryption with decryptor', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);

    const { secret, point: pub } = await ctx.generateKeypair();

    const message = await ctx.randomPoint();
    const { ciphertext, randomness, decryptor } = await elgamal.encrypt(ctx, message, pub);

    const plaintext = await elgamal.decrypt(ctx, ciphertext, { decryptor });
    expect(await plaintext.isEqual(message)).toBe(true);
  });
});


describe('encryption - decryption with decryptor failure', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);

    const { secret, point: pub } = await ctx.generateKeypair();

    const message = await ctx.randomPoint();
    const { ciphertext, randomness, decryptor } = await elgamal.encrypt(ctx, message, pub);

    const forged = await ctx.randomPoint();
    const plaintext = await elgamal.decrypt(ctx, ciphertext, { decryptor: forged });
    expect(await plaintext.isEqual(message)).toBe(false);
  });
});


describe('encryption - decryption with randomness', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);

    const { secret, point: pub } = await ctx.generateKeypair();

    const message = await ctx.randomPoint();
    const { ciphertext, randomness, decryptor } = await elgamal.encrypt(ctx, message, pub);

    const plaintext = await elgamal.decrypt(ctx, ciphertext, { randomness, pub });
    expect(await plaintext.isEqual(message)).toBe(true);
  });
});


describe('encryption - decryption with randomness failure', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);

    const { secret, point: pub } = await ctx.generateKeypair();

    const message = await ctx.randomPoint();
    const { ciphertext, randomness, decryptor } = await elgamal.encrypt(ctx, message, pub);

    const forged = await ctx.randomScalar();
    const plaintext = await elgamal.decrypt(ctx, ciphertext, { randomness: forged, pub });
    expect(await plaintext.isEqual(message)).toBe(false);
  });
});
