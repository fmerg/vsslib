import { Algorithms } from '../../src/enums';
import { initBackend, generateKey } from '../../src';
import { randomNonce } from '../../src/crypto';
import { cartesian } from '../utils';
import { buildMessage } from '../helpers';
import { resolveTestConfig } from '../environ';

const { systems, elgamalSchemes: schemes, modes, algorithms } = resolveTestConfig();


describe('Decryptor', () => {
  it.each(cartesian([systems, schemes]))('generation - over %s%/s', async (system, scheme) => {
    const ctx = initBackend(system);
    const { privateKey, publicKey } = await generateKey(ctx);
    const message = await buildMessage(ctx, scheme);
    const { ciphertext, decryptor: targetDecryptor } = await publicKey.encrypt(message, { scheme });
    const { decryptor, proof } = await privateKey.computeDecryptor(ciphertext);
    expect(decryptor).toEqual(targetDecryptor);
    expect(await publicKey.verifyDecryptor(ciphertext, decryptor, proof)).toBe(true);
  });
  it.each(cartesian([systems, schemes, algorithms]))(
    'verification - success without nonce - over %s/%s', async (system, scheme, algorithm) => {
    const ctx = initBackend(system);
    const { privateKey, publicKey } = await generateKey(ctx);
    const message = await buildMessage(ctx, scheme);
    const { ciphertext, decryptor } = await publicKey.encrypt(message, { scheme });
    const proof = await privateKey.proveDecryptor(ciphertext, decryptor, { algorithm });
    const isValid = await publicKey.verifyDecryptor(ciphertext, decryptor, proof, { algorithm });
    expect(isValid).toBe(true);
  });
  it.each(cartesian([systems, schemes, algorithms]))(
    'verification - success - over %s/%s', async (system, scheme, algorithm) => {
    const ctx = initBackend(system);
    const { privateKey, publicKey } = await generateKey(ctx);
    const message = await buildMessage(ctx, scheme);
    const { ciphertext, decryptor } = await publicKey.encrypt(message, { scheme });
    const nonce = await randomNonce();
    const proof = await privateKey.proveDecryptor(ciphertext, decryptor, { algorithm, nonce });
    const isValid = await publicKey.verifyDecryptor(ciphertext, decryptor, proof, { algorithm, nonce });
    expect(isValid).toBe(true);
  });
  it.each(cartesian([systems, schemes]))(
    'verification - failure - forged proof - over %s', async (system, scheme) => {
    const ctx = initBackend(system);
    const { privateKey, publicKey } = await generateKey(ctx);
    const message = await buildMessage(ctx, scheme);
    const { ciphertext, decryptor } = await publicKey.encrypt(message, { scheme });
    const proof = await privateKey.proveDecryptor(ciphertext, decryptor);
    proof.commitment[0] = await ctx.randomPublic();
    await expect(publicKey.verifyDecryptor(ciphertext, decryptor, proof)).rejects.toThrow(
      'Invalid decryptor'
    );
  });
  it.each(cartesian([systems, schemes, algorithms]))(
    'verification - failure - wrong algorithm - over %s/%s/%s', async (system, scheme, algorithm) => {
    const ctx = initBackend(system);
    const { privateKey, publicKey } = await generateKey(ctx);
    const message = await buildMessage(ctx, scheme);
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
  it.each(cartesian([systems, schemes]))(
    'verification - failure - missing nonce - over %s/%s', async (system, scheme) => {
    const ctx = initBackend(system);
    const { privateKey, publicKey } = await generateKey(ctx);
    const message = await buildMessage(ctx, scheme);
    const { ciphertext, decryptor } = await publicKey.encrypt(message, { scheme });
    const nonce = await randomNonce();
    const proof = await privateKey.proveDecryptor(ciphertext, decryptor, { nonce });
    await expect(publicKey.verifyDecryptor(ciphertext, decryptor, proof)).rejects.toThrow(
      'Invalid decryptor'
    );
  });
  it.each(cartesian([systems, schemes]))(
    'verification - failure - forged nonce - over %s/%s', async (system, scheme) => {
    const ctx = initBackend(system);
    const { privateKey, publicKey } = await generateKey(ctx);
    const message = await buildMessage(ctx, scheme);
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
