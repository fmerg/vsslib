import { Algorithms, AesModes, ElgamalSchemes } from '../../src/enums';
import { Algorithm } from '../../src/types';
import { generateKey } from '../../src';
import { PrivateKey, PublicKey } from '../../src/keys';
import { ErrorMessages } from '../../src/errors';
import { cartesian } from '../helpers';
import { resolveTestConfig } from '../environ';

const { systems, aesModes, algorithms } = resolveTestConfig();


describe('IES encryption and decryption', () => {
  it.each(cartesian([systems, aesModes, algorithms]))('over %s/%s/%s', async (
    system, mode, algorithm
  ) => {
    const { privateKey, publicKey, ctx } = await generateKey(system);
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const opts = { scheme: ElgamalSchemes.IES, mode, algorithm };
    const { ciphertext } = await publicKey.encrypt(message, opts);
    const plaintext = await privateKey.decrypt(ciphertext, opts);
    expect(plaintext).toEqual(message);
  });
});


describe('IES encryption proof - success without nonce', () => {
  it.each(cartesian([systems, algorithms]))('over %s/%s', async (system, algorithm) => {
    const { privateKey, publicKey, ctx } = await generateKey(system);
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const { ciphertext, randomness } = await publicKey.encrypt(message, {
      scheme: ElgamalSchemes.IES
    });
    const proof = await publicKey.proveEncryption(ciphertext, randomness, { algorithm });
    const verified = await privateKey.verifyEncryption(ciphertext, proof, { algorithm });
    expect(verified).toBe(true);
  });
});


describe('IES encryption proof - success with nonce', () => {
  it.each(cartesian([systems, algorithms]))('over %s/%s', async (system, algorithm) => {
    const { privateKey, publicKey, ctx } = await generateKey(system);
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const { ciphertext, randomness } = await publicKey.encrypt(message, {
      scheme: ElgamalSchemes.IES
    });
    const nonce = await ctx.randomBytes();
    const proof = await publicKey.proveEncryption(ciphertext, randomness, { algorithm, nonce });
    const verified = await privateKey.verifyEncryption(ciphertext, proof, { algorithm ,nonce });
    expect(verified).toBe(true);
  });
});


describe('IES encryption proof - failure if forged proof', () => {
  it.each(cartesian([systems, algorithms]))('over %s/%s', async (system, algorithm) => {
    const { privateKey, publicKey, ctx } = await generateKey(system);
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const { ciphertext, randomness } = await publicKey.encrypt(message, {
      scheme: ElgamalSchemes.IES
    });
    const proof = await publicKey.proveEncryption(ciphertext, randomness, { algorithm });
    proof.commitments[0] = await ctx.randomPoint();
    await expect(privateKey.verifyEncryption(ciphertext, proof)).rejects.toThrow(
      ErrorMessages.INVALID_ENCRYPTION
    );
  });
});


describe('IES encryption proof - failure if wrong algorithm', () => {
  it.each(cartesian([systems, algorithms]))('over %s/%s', async (system, algorithm) => {
    const { privateKey, publicKey, ctx } = await generateKey(system);
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const { ciphertext, randomness } = await publicKey.encrypt(message, {
      scheme: ElgamalSchemes.IES
    });
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


describe('IES encryption proof - failure if missing nonce', () => {
  it.each(cartesian([systems, algorithms]))('over %s/%s', async (system, algorithm) => {
    const { privateKey, publicKey, ctx } = await generateKey(system);
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const { ciphertext, randomness } = await publicKey.encrypt(message, {
      scheme: ElgamalSchemes.IES
    });
    const nonce = await ctx.randomBytes();
    const proof = await publicKey.proveEncryption(ciphertext, randomness, { algorithm, nonce });
    await expect(privateKey.verifyEncryption(ciphertext, proof, { algorithm })).rejects.toThrow(
      ErrorMessages.INVALID_ENCRYPTION
    );
  });
});


describe('IES encryption proof - failure if forged nonce', () => {
  it.each(cartesian([systems, algorithms]))('over %s/%s', async (system, algorithm) => {
    const { privateKey, publicKey, ctx } = await generateKey(system);
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const { ciphertext, randomness } = await publicKey.encrypt(message, {
      scheme: ElgamalSchemes.IES
    });
    const nonce = await ctx.randomBytes();
    const proof = await publicKey.proveEncryption(ciphertext, randomness, { algorithm, nonce });
    await expect(
      privateKey.verifyEncryption(ciphertext, proof, { nonce: await ctx.randomBytes() })
    ).rejects.toThrow(
      ErrorMessages.INVALID_ENCRYPTION
    );
  });
});


describe('Decryptor generation', () => {
  it.each(systems)('over %s', async (system) => {
    const { privateKey, publicKey, ctx } = await generateKey(system);
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const { ciphertext, decryptor: targetDecryptor } = await publicKey.encrypt(message, {
      scheme: ElgamalSchemes.IES
    });
    const { decryptor, proof } = await privateKey.generateDecryptor(ciphertext);
    expect(decryptor).toEqual(targetDecryptor);
    expect(await publicKey.verifyDecryptor(ciphertext, decryptor, proof)).toBe(true);
  });
});


describe('Decryptor proof - success without nonce', () => {
  it.each(systems)('over %s', async (system) => {
    const { privateKey, publicKey, ctx } = await generateKey(system);
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const { ciphertext, decryptor } = await publicKey.encrypt(message, {
      scheme: ElgamalSchemes.IES
    });
    const proof = await privateKey.proveDecryptor(ciphertext, decryptor);
    const verified = await publicKey.verifyDecryptor(ciphertext, decryptor, proof);
    expect(verified).toBe(true);
  });
});


describe('Decryptor proof - success with nonce', () => {
  it.each(cartesian([systems, algorithms]))('over %s/%s', async (system, algorithm) => {
    const { privateKey, publicKey, ctx } = await generateKey(system);
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const { ciphertext, decryptor } = await publicKey.encrypt(message, {
      scheme: ElgamalSchemes.IES
    });
    const nonce = await ctx.randomBytes();
    const proof = await privateKey.proveDecryptor(ciphertext, decryptor, { algorithm, nonce });
    const verified = await publicKey.verifyDecryptor(ciphertext, decryptor, proof, { algorithm, nonce });
    expect(verified).toBe(true);
  });
});


describe('Decryptor proof - failure if forged proof', () => {
  it.each(systems)('over %s', async (system) => {
    const { privateKey, publicKey, ctx } = await generateKey(system);
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const { ciphertext, decryptor } = await publicKey.encrypt(message, {
      scheme: ElgamalSchemes.IES
    });
    const proof = await privateKey.proveDecryptor(ciphertext, decryptor);
    proof.commitments[0] = await ctx.randomPoint();
    await expect(publicKey.verifyDecryptor(ciphertext, decryptor, proof)).rejects.toThrow(
      ErrorMessages.INVALID_DECRYPTOR
    );
  });
});


describe('Decryptor proof - failure if wrong algorithm', () => {
  it.each(cartesian([systems, algorithms]))('over %s/%s', async (system, algorithm) => {
    const { privateKey, publicKey, ctx } = await generateKey(system);
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const { ciphertext, decryptor } = await publicKey.encrypt(message, {
      scheme: ElgamalSchemes.IES
    });
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
  it.each(systems)('over %s', async (system) => {
    const { privateKey, publicKey, ctx } = await generateKey(system);
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const { ciphertext, decryptor } = await publicKey.encrypt(message, {
      scheme: ElgamalSchemes.IES
    });
    const nonce = await ctx.randomBytes();
    const proof = await privateKey.proveDecryptor(ciphertext, decryptor, { nonce });
    await expect(publicKey.verifyDecryptor(ciphertext, decryptor, proof)).rejects.toThrow(
      ErrorMessages.INVALID_DECRYPTOR
    );
  });
});


describe('Decryptor proof - failure if forged nonce', () => {
  it.each(systems)('over %s', async (system) => {
    const { privateKey, publicKey, ctx } = await generateKey(system);
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const { ciphertext, decryptor } = await publicKey.encrypt(message, {
      scheme: ElgamalSchemes.IES
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
