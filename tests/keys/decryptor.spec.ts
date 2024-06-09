import { Algorithms } from '../../src/enums';
import { generateKey } from '../../src';
import { randomNonce } from '../../src/crypto';
import { cartesian } from '../utils';
import { mockMessage } from '../helpers';
import { resolveTestConfig } from '../environ';

const { systems, elgamalSchemes: schemes, aesModes, algorithms } = resolveTestConfig();


describe('generation', () => {
  it.each(cartesian([systems, schemes]))('over %s%/s', async (system, scheme) => {
    const { privateKey, publicKey, ctx } = await generateKey(system);
    const message = await mockMessage(ctx, scheme);
    const { ciphertext, decryptor: targetDecryptor } = await publicKey.encrypt(message, { scheme });
    const { decryptor, proof } = await privateKey.computeDecryptor(ciphertext);
    expect(decryptor).toEqual(targetDecryptor);
    expect(await publicKey.verifyDecryptor(ciphertext, decryptor, proof)).toBe(true);
  });
});


describe('proof - success without nonce', () => {
  it.each(cartesian([systems, schemes, algorithms]))('over %s/%s', async (
    system, scheme, algorithm
  ) => {
    const { privateKey, publicKey, ctx } = await generateKey(system);
    const message = await mockMessage(ctx, scheme);
    const { ciphertext, decryptor } = await publicKey.encrypt(message, { scheme });
    const proof = await privateKey.proveDecryptor(ciphertext, decryptor, { algorithm });
    const verified = await publicKey.verifyDecryptor(ciphertext, decryptor, proof, { algorithm });
    expect(verified).toBe(true);
  });
});


describe('proof - success with nonce', () => {
  it.each(cartesian([systems, schemes, algorithms]))('over %s/%s', async (
    system, scheme, algorithm
  ) => {
    const { privateKey, publicKey, ctx } = await generateKey(system);
    const message = await mockMessage(ctx, scheme);
    const { ciphertext, decryptor } = await publicKey.encrypt(message, { scheme });
    const nonce = await randomNonce();
    const proof = await privateKey.proveDecryptor(ciphertext, decryptor, { algorithm, nonce });
    const verified = await publicKey.verifyDecryptor(ciphertext, decryptor, proof, { algorithm, nonce });
    expect(verified).toBe(true);
  });
});


describe('proof - failure if forged proof', () => {
  it.each(cartesian([systems, schemes]))('over %s', async (system, scheme) => {
    const { privateKey, publicKey, ctx } = await generateKey(system);
    const message = await mockMessage(ctx, scheme);
    const { ciphertext, decryptor } = await publicKey.encrypt(message, { scheme });
    const proof = await privateKey.proveDecryptor(ciphertext, decryptor);
    proof.commitment[0] = (await ctx.randomPoint()).toBytes();
    await expect(publicKey.verifyDecryptor(ciphertext, decryptor, proof)).rejects.toThrow(
      'Invalid decryptor'
    );
  });
});


describe('proof - failure if wrong algorithm', () => {
  it.each(cartesian([systems, schemes, algorithms]))('over %s/%s/%s', async (
    system, scheme, algorithm
  ) => {
    const { privateKey, publicKey, ctx } = await generateKey(system);
    const message = await mockMessage(ctx, scheme);
    const { ciphertext, decryptor } = await publicKey.encrypt(message, { scheme });
    const proof = await privateKey.proveDecryptor(ciphertext, decryptor, { algorithm });
    await expect(
      publicKey.verifyDecryptor(ciphertext, decryptor, proof, {
        algorithm: algorithm == Algorithms.SHA256 ?
          Algorithms.SHA512 :
          Algorithms.SHA256
      })
    ).rejects.toThrow(
      'Invalid decryptor'
    );
  });
});


describe('proof - failure if missing nonce', () => {
  it.each(cartesian([systems, schemes]))('over %s/%s', async (system, scheme) => {
    const { privateKey, publicKey, ctx } = await generateKey(system);
    const message = await mockMessage(ctx, scheme);
    const { ciphertext, decryptor } = await publicKey.encrypt(message, { scheme });
    const nonce = await randomNonce();
    const proof = await privateKey.proveDecryptor(ciphertext, decryptor, { nonce });
    await expect(publicKey.verifyDecryptor(ciphertext, decryptor, proof)).rejects.toThrow(
      'Invalid decryptor'
    );
  });
});


describe('proof - failure if forged nonce', () => {
  it.each(cartesian([systems, schemes]))('over %s/%s', async (system, scheme) => {
    const { privateKey, publicKey, ctx } = await generateKey(system);
    const message = await mockMessage(ctx, scheme);
    const { ciphertext, decryptor } = await publicKey.encrypt(message, { scheme });
    const nonce = await randomNonce();
    const proof = await privateKey.proveDecryptor(ciphertext, decryptor, { nonce });
    await expect(
      publicKey.verifyDecryptor(ciphertext, decryptor, proof, { nonce: await randomNonce() })
    ).rejects.toThrow(
      'Invalid decryptor'
    );
  });
});
