import { elgamal, backend, utils } from '../src';
import { Systems, Algorithms } from '../src/enums';
import { Algorithm } from '../src/types';
import { cartesian } from './helpers';


const __labels      = Object.values(Systems);
const __algorithms  = [...Object.values(Algorithms), undefined];


describe('encryption - decryption with secret key failure', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);

    const secret = await ctx.randomScalar();
    const pub = await ctx.operate(secret, ctx.generator);

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

    const secret = await ctx.randomScalar();
    const pub = await ctx.operate(secret, ctx.generator);

    const message = await ctx.randomPoint();
    const { ciphertext, randomness, decryptor } = await elgamal.encrypt(ctx, message, pub);

    const plaintext = await elgamal.decrypt(ctx, ciphertext, { decryptor });
    expect(await plaintext.isEqual(message)).toBe(true);
  });
});


describe('encryption - decryption with decryptor failure', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);

    const secret = await ctx.randomScalar();
    const pub = await ctx.operate(secret, ctx.generator);

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

    const secret = await ctx.randomScalar();
    const pub = await ctx.operate(secret, ctx.generator);

    const message = await ctx.randomPoint();
    const { ciphertext, randomness, decryptor } = await elgamal.encrypt(ctx, message, pub);

    const plaintext = await elgamal.decrypt(ctx, ciphertext, { randomness, pub });
    expect(await plaintext.isEqual(message)).toBe(true);
  });
});


describe('encryption - decryption with randomness failure', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);

    const secret = await ctx.randomScalar();
    const pub = await ctx.operate(secret, ctx.generator);

    const message = await ctx.randomPoint();
    const { ciphertext, randomness, decryptor } = await elgamal.encrypt(ctx, message, pub);

    const forged = await ctx.randomScalar();
    const plaintext = await elgamal.decrypt(ctx, ciphertext, { randomness: forged, pub });
    expect(await plaintext.isEqual(message)).toBe(false);
  });
});


describe('encryption - proof of encryption', () => {
  it.each(cartesian([__labels, __algorithms]))('over %s/%s', async (label, algorithm) => {
    const ctx = backend.initGroup(label);

    const secret = await ctx.randomScalar();
    const pub = await ctx.operate(secret, ctx.generator);

    const message = await ctx.randomPoint();
    const { ciphertext, randomness } = await elgamal.encrypt(ctx, message, pub);
    const proof = await elgamal.proveEncryption(ctx, ciphertext, randomness, {
      algorithm
    });
    expect(proof.algorithm).toBe(algorithm || Algorithms.DEFAULT);

    const valid = await elgamal.verifyEncryption(ctx, ciphertext, proof);
    expect(valid).toBe(true);
  });
});


describe('encryption - proof of encryption failure', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);

    const secret = await ctx.randomScalar();
    const pub = await ctx.operate(secret, ctx.generator);

    const message = await ctx.randomPoint();
    const { ciphertext, randomness } = await elgamal.encrypt(ctx, message, pub);
    const proof = await elgamal.proveEncryption(ctx, ciphertext, randomness);

    // Tamper ciphertext
    ciphertext.beta = await ctx.randomPoint();

    const valid = await elgamal.verifyEncryption(ctx, ciphertext, proof);
    expect(valid).toBe(false);
  });
});


describe('encryption - proof of decryptor', () => {
  it.each(cartesian([__labels, __algorithms]))('over %s/%s', async (label, algorithm) => {
    const ctx = backend.initGroup(label);

    const secret = await ctx.randomScalar();
    const pub = await ctx.operate(secret, ctx.generator);

    const message = await ctx.randomPoint();
    const { ciphertext, decryptor } = await elgamal.encrypt(ctx, message, pub);
    const proof = await elgamal.proveDecryptor(ctx, ciphertext, secret, decryptor, {
      algorithm
    });
    expect(proof.algorithm).toBe(algorithm || Algorithms.DEFAULT);

    const valid = await elgamal.verifyDecryptor(ctx, ciphertext, pub, decryptor, proof);
    expect(valid).toBe(true);
  });
});


describe('encryption - proof of decryptor failure', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);

    const secret = await ctx.randomScalar();
    const pub = await ctx.operate(secret, ctx.generator);

    const message = await ctx.randomPoint();
    const { ciphertext, decryptor } = await elgamal.encrypt(ctx, message, pub);
    const proof = await elgamal.proveDecryptor(ctx, ciphertext, secret, decryptor);

    const forged = await ctx.randomPoint();
    const valid = await elgamal.verifyDecryptor(ctx, ciphertext, pub, forged, proof);
    expect(valid).toBe(false);
  });
});
