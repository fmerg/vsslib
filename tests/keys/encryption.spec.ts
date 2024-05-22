import { Algorithms, AesModes, ElgamalSchemes } from '../../src/enums';
import { Algorithm, ElgamalScheme } from '../../src/types';
import { generateKey } from '../../src';
import { PrivateKey, PublicKey } from '../../src/keys';
import { ErrorMessages } from '../../src/errors';
import { randomNonce } from '../../src/crypto';
import { cartesian } from '../helpers';
import { resolveTestConfig } from '../environ';
import { Point, Group } from '../../src/backend/abstract';

const { systems, elgamalSchemes: schemes, aesModes, algorithms } = resolveTestConfig();


const mockMessage = async (
  ctx: Group<Point>, scheme: ElgamalScheme
) => scheme == ElgamalSchemes.PLAIN ? (await ctx.randomPoint()).toBytes() :
  Uint8Array.from(Buffer.from('destroy earth'));



describe('encrypt and decrypt', () => {
  it.each(cartesian([systems, schemes, aesModes, algorithms]))('over %s/%s/%s/%s', async (
    system, scheme, mode, algorithm
  ) => {
    const { privateKey, publicKey, ctx } = await generateKey(system);
    const message = await mockMessage(ctx, scheme);
    const opts = { scheme, mode, algorithm };
    const { ciphertext } = await publicKey.encrypt(message, opts);
    const plaintext = await privateKey.decrypt(ciphertext, opts);
    expect(plaintext).toEqual(message);
  });
});


describe('encrypt and decrypt - invalid point encoding', () => {
  it.each(systems)('over %s', async (system) => {
    const { privateKey, publicKey, ctx } = await generateKey(system);
    const message = new Uint8Array([0, 1, 666, 999]);
    expect(publicKey.encrypt(message, { scheme: ElgamalSchemes.PLAIN })).rejects.toThrow(
      'bad encoding:'
    );
  });
});


describe('encrypt-then-prove - success without nonce', () => {
  it.each(cartesian([systems, schemes, algorithms]))('over %s/%s/%s', async (
    system, scheme, algorithm
  ) => {
    const { privateKey, publicKey, ctx } = await generateKey(system);
    const message = await mockMessage(ctx, scheme);
    const { ciphertext, randomness } = await publicKey.encrypt(message, { scheme });
    const proof = await publicKey.proveEncryption(ciphertext, randomness, { algorithm });
    const verified = await privateKey.verifyEncryption(ciphertext, proof, { algorithm });
    expect(verified).toBe(true);
  });
});


describe('encrypt-then-prove - success with nonce', () => {
  it.each(cartesian([systems, schemes, algorithms]))('over %s/%s/%s', async (
    system, scheme, algorithm
  ) => {
    const { privateKey, publicKey, ctx } = await generateKey(system);
    const message = await mockMessage(ctx, scheme);
    const { ciphertext, randomness } = await publicKey.encrypt(message, { scheme });
    const nonce = await randomNonce();
    const proof = await publicKey.proveEncryption(ciphertext, randomness, { algorithm, nonce });
    const verified = await privateKey.verifyEncryption(ciphertext, proof, { algorithm, nonce });
    expect(verified).toBe(true);
  });
});


describe('encrypt-then-prove - failure if forged proof', () => {
  it.each(cartesian([systems, schemes, algorithms]))('over %s/%s/%s', async (
    system, scheme, algorithm
  ) => {
    const { privateKey, publicKey, ctx } = await generateKey(system);
    const message = await mockMessage(ctx, scheme);
    const { ciphertext, randomness } = await publicKey.encrypt(message, { scheme });
    const proof = await publicKey.proveEncryption(ciphertext, randomness, { algorithm });
    proof.commitment[0] = (await ctx.randomPoint()).toBytes();
    await expect(privateKey.verifyEncryption(ciphertext, proof)).rejects.toThrow(
      ErrorMessages.INVALID_ENCRYPTION
    );
  });
});


describe('encrypt-then-prove - failure if wrong algorithm', () => {
  it.each(cartesian([systems, schemes, algorithms]))('over %s/%s/%s', async (
    system, scheme, algorithm
  ) => {
    const { privateKey, publicKey, ctx } = await generateKey(system);
    const message = await mockMessage(ctx, scheme);
    const { ciphertext, randomness } = await publicKey.encrypt(message, { scheme });
    const proof = await publicKey.proveEncryption(ciphertext, randomness, { algorithm });
    await expect(
      privateKey.verifyEncryption(ciphertext, proof, {
        algorithm: algorithm == Algorithms.SHA256 ?
          Algorithms.SHA512 :
          Algorithms.SHA256
      })
    ).rejects.toThrow(
      ErrorMessages.INVALID_ENCRYPTION
    );
  });
});


describe('encrypt-then-prove - failure if missing nonce', () => {
  it.each(cartesian([systems, schemes, algorithms]))('over %s/%s/%s', async (
    system, scheme, algorithm
  ) => {
    const { privateKey, publicKey, ctx } = await generateKey(system);
    const message = await mockMessage(ctx, scheme);
    const { ciphertext, randomness } = await publicKey.encrypt(message, { scheme });
    const nonce = await randomNonce();
    const proof = await publicKey.proveEncryption(ciphertext, randomness, { algorithm, nonce });
    await expect(privateKey.verifyEncryption(ciphertext, proof, { algorithm })).rejects.toThrow(
      ErrorMessages.INVALID_ENCRYPTION
    );
  });
});


describe('encrypt-then-prove - failure if forged nonce', () => {
  it.each(cartesian([systems, schemes, algorithms]))('over %s/%s/%s', async (
    system, scheme, algorithm
  ) => {
    const { privateKey, publicKey, ctx } = await generateKey(system);
    const message = await mockMessage(ctx, scheme);
    const { ciphertext, randomness } = await publicKey.encrypt(message, { scheme });
    const nonce = await randomNonce();
    const proof = await publicKey.proveEncryption(ciphertext, randomness, { algorithm, nonce });
    await expect(
      privateKey.verifyEncryption(ciphertext, proof, { nonce: await randomNonce() })
    ).rejects.toThrow(
      ErrorMessages.INVALID_ENCRYPTION
    );
  });
});


describe('Decryptor generation', () => {
  it.each(cartesian([systems, schemes]))('over %s%/s', async (system, scheme) => {
    const { privateKey, publicKey, ctx } = await generateKey(system);
    const message = await mockMessage(ctx, scheme);
    const { ciphertext, decryptor: targetDecryptor } = await publicKey.encrypt(message, { scheme });
    const { decryptor, proof } = await privateKey.generateDecryptor(ciphertext);
    expect(decryptor).toEqual(targetDecryptor);
    expect(await publicKey.verifyDecryptor(ciphertext, decryptor, proof)).toBe(true);
  });
});


describe('Decryptor proof - success without nonce', () => {
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


describe('Decryptor proof - success with nonce', () => {
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


describe('Decryptor proof - failure if forged proof', () => {
  it.each(cartesian([systems, schemes]))('over %s', async (system, scheme) => {
    const { privateKey, publicKey, ctx } = await generateKey(system);
    const message = await mockMessage(ctx, scheme);
    const { ciphertext, decryptor } = await publicKey.encrypt(message, { scheme });
    const proof = await privateKey.proveDecryptor(ciphertext, decryptor);
    proof.commitment[0] = (await ctx.randomPoint()).toBytes();
    await expect(publicKey.verifyDecryptor(ciphertext, decryptor, proof)).rejects.toThrow(
      ErrorMessages.INVALID_DECRYPTOR
    );
  });
});


describe('Decryptor proof - failure if wrong algorithm', () => {
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
      ErrorMessages.INVALID_DECRYPTOR
    );
  });
});


describe('Decryptor proof - failure if missing nonce', () => {
  it.each(cartesian([systems, schemes]))('over %s/%s', async (system, scheme) => {
    const { privateKey, publicKey, ctx } = await generateKey(system);
    const message = await mockMessage(ctx, scheme);
    const { ciphertext, decryptor } = await publicKey.encrypt(message, { scheme });
    const nonce = await randomNonce();
    const proof = await privateKey.proveDecryptor(ciphertext, decryptor, { nonce });
    await expect(publicKey.verifyDecryptor(ciphertext, decryptor, proof)).rejects.toThrow(
      ErrorMessages.INVALID_DECRYPTOR
    );
  });
});


describe('Decryptor proof - failure if forged nonce', () => {
  it.each(cartesian([systems, schemes]))('over %s/%s', async (system, scheme) => {
    const { privateKey, publicKey, ctx } = await generateKey(system);
    const message = await mockMessage(ctx, scheme);
    const { ciphertext, decryptor } = await publicKey.encrypt(message, { scheme });
    const nonce = await randomNonce();
    const proof = await privateKey.proveDecryptor(ciphertext, decryptor, { nonce });
    await expect(
      publicKey.verifyDecryptor(ciphertext, decryptor, proof, { nonce: await randomNonce() })
    ).rejects.toThrow(
      ErrorMessages.INVALID_DECRYPTOR
    );
  });
});
