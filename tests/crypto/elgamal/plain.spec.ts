import { Systems } from '../../../src/schemes';
import { plain, backend } from '../../../src';
import { cartesian } from '../../helpers';
import { resolveTestConfig } from '../../environ';

const { labels, aesModes } = resolveTestConfig();


describe('Decryption - success', () => {
  it.each(labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const { secret, pub } = await ctx.generateKeypair();
    const message = (await ctx.randomPoint()).toBytes();
    const { ciphertext } = await plain(ctx).encrypt(message, pub);
    const plaintext = await plain(ctx).decrypt(ciphertext, secret);
    expect(plaintext).toEqual(message);
  });
});


describe('Decryption - failure if forged secret', () => {
  it.each(labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const { secret, pub } = await ctx.generateKeypair();
    const message = (await ctx.randomPoint()).toBytes();
    const { ciphertext } = await plain(ctx).encrypt(message, pub);
    const forgedSecret = await ctx.randomScalar();
    const plaintext = await plain(ctx).decrypt(ciphertext, forgedSecret);
    expect(plaintext).not.toEqual(message);
  });
});


describe('Decryption with decryptor - success', () => {
  it.each(labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const { secret, pub } = await ctx.generateKeypair();
    const message = (await ctx.randomPoint()).toBytes();
    const { ciphertext, decryptor } = await plain(ctx).encrypt(message, pub);
    const plaintext = await plain(ctx).decryptWithDecryptor(ciphertext, decryptor);
    expect(plaintext).toEqual(message);
  });
});


describe('Decryption with decryptor - failure if forged decryptor', () => {
  it.each(labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const { secret, pub } = await ctx.generateKeypair();
    const message = (await ctx.randomPoint()).toBytes();
    const { ciphertext, decryptor } = await plain(ctx).encrypt(message, pub);
    const forgedDecryptor = await ctx.randomPoint();
    const plaintext = await plain(ctx).decryptWithDecryptor(ciphertext, forgedDecryptor);
    expect(plaintext).not.toEqual(message);
  });
});


describe('Decryption with randomness - success', () => {
  it.each(labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const { secret, pub } = await ctx.generateKeypair();
    const message = (await ctx.randomPoint()).toBytes();
    const { ciphertext, randomness } = await plain(ctx).encrypt(message, pub);
    const plaintext = await plain(ctx).decryptWithRandomness(ciphertext, pub, randomness);
    expect(plaintext).toEqual(message);
  });
});


describe('Decryption with randomness - failure if forged randomness', () => {
  it.each(labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const { secret, pub } = await ctx.generateKeypair();
    const message = (await ctx.randomPoint()).toBytes();
    const { ciphertext, randomness } = await plain(ctx).encrypt(message, pub);
    const forgedRandomnes = await ctx.randomScalar();
    const plaintext = await plain(ctx).decryptWithRandomness(ciphertext, pub, forgedRandomnes);
    expect(plaintext).not.toEqual(message);
  });
});
