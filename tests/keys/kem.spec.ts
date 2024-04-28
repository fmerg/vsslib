import { Algorithms, AesModes, ElgamalSchemes } from '../../src/enums';
import { Algorithm } from '../../src/types';
import { generateKey } from '../../src/core';
import { PrivateKey, PublicKey } from '../../src/keys';
import { ErrorMessages } from '../../src/errors';
import { cartesian } from '../helpers';
import { resolveTestConfig } from '../environ';

let { labels, aesModes, algorithms } = resolveTestConfig();

algorithms  = [...algorithms, undefined];
aesModes    = [...aesModes, undefined];


describe('KEM hybrid encryption and decryption', () => {
  it.each(cartesian([labels, aesModes]))('over %s/%s', async (label, mode) => {
    const { privateKey, publicKey, ctx } = await generateKey(label);
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const opts = { scheme: ElgamalSchemes.KEM, mode };
    const { ciphertext } = await publicKey.encrypt(message, opts)
    const plaintext = await privateKey.decrypt(ciphertext, opts);
    expect(plaintext).toEqual(message);
  });
});


describe('KEM hybrid encryption proof - success without nonce', () => {
  it.each(cartesian([labels, algorithms]))('over %s/%s', async (label, algorithm) => {
    const { privateKey, publicKey, ctx } = await generateKey(label);
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const { ciphertext, randomness } = await publicKey.encrypt(message, {
      scheme: ElgamalSchemes.KEM
    });
    const proof = await publicKey.proveEncryption(ciphertext, randomness, { algorithm });
    expect(proof.algorithm).toBe(algorithm || Algorithms.DEFAULT);
    const verified = await privateKey.verifyEncryption(ciphertext, proof);
    expect(verified).toBe(true);
  });
});


describe('KEM hybrid encryption proof - success with nonce', () => {
  it.each(cartesian([labels, algorithms]))('over %s/%s', async (label, algorithm) => {
    const { privateKey, publicKey, ctx } = await generateKey(label);
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const { ciphertext, randomness } = await publicKey.encrypt(message, {
      scheme: ElgamalSchemes.KEM
    });
    const nonce = await ctx.randomBytes();
    const proof = await publicKey.proveEncryption(ciphertext, randomness, { algorithm, nonce });
    expect(proof.algorithm).toBe(algorithm || Algorithms.DEFAULT);
    const verified = await privateKey.verifyEncryption(ciphertext, proof, { nonce });
    expect(verified).toBe(true);
  });
});


describe('KEM hybrid encryption proof - failure if forged proof', () => {
  it.each(cartesian([labels, algorithms]))('over %s/%s', async (label, algorithm) => {
    const { privateKey, publicKey, ctx } = await generateKey(label);
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const { ciphertext, randomness } = await publicKey.encrypt(message, {
      scheme: ElgamalSchemes.KEM
    });
    const proof = await publicKey.proveEncryption(ciphertext, randomness, { algorithm });
    proof.commitments[0] = await ctx.randomPoint();
    await expect(privateKey.verifyEncryption(ciphertext, proof)).rejects.toThrow(
      ErrorMessages.INVALID_ENCRYPTION
    );
  });
});


describe('KEM hybrid encryption proof - failure if wrong algorithm', () => {
  it.each(cartesian([labels, algorithms]))('over %s/%s', async (label, algorithm) => {
    const { privateKey, publicKey, ctx } = await generateKey(label);
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const { ciphertext, randomness } = await publicKey.encrypt(message, {
      scheme: ElgamalSchemes.KEM
    });
    const proof = await publicKey.proveEncryption(ciphertext, randomness, { algorithm });
    proof.algorithm = (proof.algorithm == Algorithms.SHA256) ?
      Algorithms.SHA512 :
      Algorithms.SHA256;
    await expect(privateKey.verifyEncryption(ciphertext, proof)).rejects.toThrow(
      ErrorMessages.INVALID_ENCRYPTION
    );
  });
});


describe('KEM hybrid encryption proof - failure if missing nonce', () => {
  it.each(cartesian([labels, algorithms]))('over %s/%s', async (label, algorithm) => {
    const { privateKey, publicKey, ctx } = await generateKey(label);
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const { ciphertext, randomness } = await publicKey.encrypt(message, {
      scheme: ElgamalSchemes.KEM
    });
    const nonce = await ctx.randomBytes();
    const proof = await publicKey.proveEncryption(ciphertext, randomness, { algorithm, nonce });
    await expect(privateKey.verifyEncryption(ciphertext, proof)).rejects.toThrow(
      ErrorMessages.INVALID_ENCRYPTION
    );
  });
});


describe('KEM hybrid encryption proof - failure if forged nonce', () => {
  it.each(cartesian([labels, algorithms]))('over %s/%s', async (label, algorithm) => {
    const { privateKey, publicKey, ctx } = await generateKey(label);
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const { ciphertext, randomness } = await publicKey.encrypt(message, {
      scheme: ElgamalSchemes.KEM
    });
    const nonce = await ctx.randomBytes();
    const proof = await publicKey.proveEncryption(ciphertext, randomness, { algorithm, nonce });
    await expect(
      privateKey.verifyEncryption(ciphertext, proof, { nonce: await privateKey.ctx.randomBytes() })
    ).rejects.toThrow(
      ErrorMessages.INVALID_ENCRYPTION
    );
  });
});


describe('Decryptor generation', () => {
  it.each(labels)('over %s', async (label) => {
    const { privateKey, publicKey, ctx } = await generateKey(label);
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const { ciphertext, decryptor: targetDecryptor } = await publicKey.encrypt(message, {
      scheme: ElgamalSchemes.KEM
    });
    const { decryptor, proof } = await privateKey.generateDecryptor(ciphertext);
    expect(await decryptor.equals(targetDecryptor)).toBe(true);
    expect(await publicKey.verifyDecryptor(ciphertext, decryptor, proof)).toBe(true);
  });
});


describe('Decryptor proof - success without nonce', () => {
  it.each(labels)('over %s', async (label) => {
    const { privateKey, publicKey, ctx } = await generateKey(label);
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const { ciphertext, decryptor } = await publicKey.encrypt(message, {
      scheme: ElgamalSchemes.KEM
    });
    const proof = await privateKey.proveDecryptor(ciphertext, decryptor);
    const verified = await publicKey.verifyDecryptor(ciphertext, decryptor, proof);
    expect(verified).toBe(true);
  });
});


describe('Decryptor proof - success with nonce', () => {
  it.each(cartesian([labels, algorithms]))('over %s/%s', async (label, algorithm) => {
    const { privateKey, publicKey, ctx } = await generateKey(label);
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const { ciphertext, decryptor } = await publicKey.encrypt(message, {
      scheme: ElgamalSchemes.KEM
    });
    const nonce = await ctx.randomBytes();
    const proof = await privateKey.proveDecryptor(ciphertext, decryptor, { algorithm, nonce });
    expect(proof.algorithm).toBe(algorithm || Algorithms.DEFAULT);
    const verified = await publicKey.verifyDecryptor(ciphertext, decryptor, proof, { nonce });
    expect(verified).toBe(true);
  });
});


describe('Decryptor proof - failure if forged proof', () => {
  it.each(labels)('over %s', async (label) => {
    const { privateKey, publicKey, ctx } = await generateKey(label);
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const { ciphertext, decryptor } = await publicKey.encrypt(message, {
      scheme: ElgamalSchemes.KEM
    });
    const proof = await privateKey.proveDecryptor(ciphertext, decryptor);
    proof.commitments[0] = await ctx.randomPoint();
    await expect(publicKey.verifyDecryptor(ciphertext, decryptor, proof)).rejects.toThrow(
      ErrorMessages.INVALID_DECRYPTOR
    );
  });
});


describe('Decryptor proof - failure if wrong algorithm', () => {
  it.each(cartesian([labels, algorithms]))('over %s/%s', async (label, algorithm) => {
    const { privateKey, publicKey, ctx } = await generateKey(label);
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const { ciphertext, decryptor } = await publicKey.encrypt(message, {
      scheme: ElgamalSchemes.KEM
    });
    const proof = await privateKey.proveDecryptor(ciphertext, decryptor, { algorithm });
    proof.algorithm = (proof.algorithm == Algorithms.SHA256) ?
      Algorithms.SHA512 :
      Algorithms.SHA256;
    await expect(publicKey.verifyDecryptor(ciphertext, decryptor, proof)).rejects.toThrow(
      ErrorMessages.INVALID_DECRYPTOR
    );
  });
});


describe('Decryptor proof - failure if missing nonce', () => {
  it.each(labels)('over %s', async (label) => {
    const { privateKey, publicKey, ctx } = await generateKey(label);
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const { ciphertext, decryptor } = await publicKey.encrypt(message, {
      scheme: ElgamalSchemes.KEM
    });
    const nonce = await ctx.randomBytes();
    const proof = await privateKey.proveDecryptor(ciphertext, decryptor, { nonce });
    await expect(publicKey.verifyDecryptor(ciphertext, decryptor, proof)).rejects.toThrow(
      ErrorMessages.INVALID_DECRYPTOR
    );
  });
});


describe('Decryptor proof - failure if forged nonce', () => {
  it.each(labels)('over %s', async (label) => {
    const { privateKey, publicKey, ctx } = await generateKey(label);
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const { ciphertext, decryptor } = await publicKey.encrypt(message, {
      scheme: ElgamalSchemes.KEM
    });
    const nonce = await ctx.randomBytes();
    const proof = await privateKey.proveDecryptor(ciphertext, decryptor, { nonce });
    await expect(
      publicKey.verifyDecryptor(ciphertext, decryptor, proof, { nonce: await ctx.randomBytes() })
    ).rejects.toThrow(
      ErrorMessages.INVALID_DECRYPTOR
    );
  });
});
