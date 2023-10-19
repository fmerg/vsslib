import { Systems, Algorithms } from '../src/enums';
import { Algorithm } from '../src/types';
import { cartesian } from './helpers';

const elgamal = require('../src/elgamal');
const utils = require('../src/utils');


const __labels      = Object.values(Systems);
const __algorithms  = [...Object.values(Algorithms), undefined];


describe('encryption - decryption with secret key failure', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = elgamal.initCrypto(label);

    const secret = await ctx.randomScalar();
    const pub = await ctx.operate(secret, ctx.generator);

    const message = await ctx.randomPoint();
    const { ciphertext, randomness, decryptor } = await ctx.encrypt(message, pub);

    const forged = await ctx.randomScalar();
    const plaintext = await ctx.decrypt(ciphertext, { secret: forged });
    expect(await plaintext.isEqual(message)).toBe(false);
  });
});


describe('encryption - decryption with decryptor', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = elgamal.initCrypto(label);

    const secret = await ctx.randomScalar();
    const pub = await ctx.operate(secret, ctx.generator);

    const message = await ctx.randomPoint();
    const { ciphertext, randomness, decryptor } = await ctx.encrypt(message, pub);

    const plaintext = await ctx.decrypt(ciphertext, { decryptor });
    expect(await plaintext.isEqual(message)).toBe(true);
  });
});


describe('encryption - decryption with decryptor failure', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = elgamal.initCrypto(label);

    const secret = await ctx.randomScalar();
    const pub = await ctx.operate(secret, ctx.generator);

    const message = await ctx.randomPoint();
    const { ciphertext, randomness, decryptor } = await ctx.encrypt(message, pub);

    const forged = await ctx.randomPoint();
    const plaintext = await ctx.decrypt(ciphertext, { decryptor: forged });
    expect(await plaintext.isEqual(message)).toBe(false);
  });
});


describe('encryption - decryption with randomness', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = elgamal.initCrypto(label);

    const secret = await ctx.randomScalar();
    const pub = await ctx.operate(secret, ctx.generator);

    const message = await ctx.randomPoint();
    const { ciphertext, randomness, decryptor } = await ctx.encrypt(message, pub);

    const plaintext = await ctx.decrypt(ciphertext, { randomness, pub });
    expect(await plaintext.isEqual(message)).toBe(true);
  });
});


describe('encryption - decryption with randomness failure', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = elgamal.initCrypto(label);

    const secret = await ctx.randomScalar();
    const pub = await ctx.operate(secret, ctx.generator);

    const message = await ctx.randomPoint();
    const { ciphertext, randomness, decryptor } = await ctx.encrypt(message, pub);

    const forged = await ctx.randomScalar();
    const plaintext = await ctx.decrypt(ciphertext, { randomness: forged, pub });
    expect(await plaintext.isEqual(message)).toBe(false);
  });
});


describe('encryption - proof of encryption', () => {
  it.each(cartesian([__labels, __algorithms]))('over %s/%s', async (label, algorithm) => {
    const ctx = elgamal.initCrypto(label);

    const secret = await ctx.randomScalar();
    const pub = await ctx.operate(secret, ctx.generator);

    const message = await ctx.randomPoint();
    const { ciphertext, randomness } = await ctx.encrypt(message, pub);
    const proof = await ctx.proveEncryption(ciphertext, randomness, {
      algorithm
    });
    expect(proof.algorithm).toBe(algorithm || Algorithms.DEFAULT);

    const valid = await ctx.verifyEncryption(ciphertext, proof);
    expect(valid).toBe(true);
  });
});


describe('encryption - proof of encryption failure', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = elgamal.initCrypto(label);

    const secret = await ctx.randomScalar();
    const pub = await ctx.operate(secret, ctx.generator);

    const message = await ctx.randomPoint();
    const { ciphertext, randomness } = await ctx.encrypt(message, pub);
    const proof = await ctx.proveEncryption(ciphertext, randomness);

    // Tamper ciphertext
    ciphertext.beta = await ctx.randomPoint();

    const valid = await ctx.verifyEncryption(ciphertext, proof);
    expect(valid).toBe(false);
  });
});


describe('encryption - proof of decryptor', () => {
  it.each(cartesian([__labels, __algorithms]))('over %s/%s', async (label, algorithm) => {
    const ctx = elgamal.initCrypto(label);

    const secret = await ctx.randomScalar();
    const pub = await ctx.operate(secret, ctx.generator);

    const message = await ctx.randomPoint();
    const { ciphertext, decryptor } = await ctx.encrypt(message, pub);
    const proof = await ctx.proveDecryptor(ciphertext, secret, decryptor, {
      algorithm
    });
    expect(proof.algorithm).toBe(algorithm || Algorithms.DEFAULT);

    const valid = await ctx.verifyDecryptor(decryptor, ciphertext, pub, proof);
    expect(valid).toBe(true);
  });
});


describe('encryption - proof of decryptor failure', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = elgamal.initCrypto(label);

    const secret = await ctx.randomScalar();
    const pub = await ctx.operate(secret, ctx.generator);

    const message = await ctx.randomPoint();
    const { ciphertext, decryptor } = await ctx.encrypt(message, pub);
    const proof = await ctx.proveDecryptor(ciphertext, secret, decryptor);

    const forged = await ctx.randomPoint();
    const valid = await ctx.verifyDecryptor(forged, ciphertext, pub, proof);
    expect(valid).toBe(false);
  });
});
