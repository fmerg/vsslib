import { Algorithms, Algorithm, Systems, ElgamalSchemes } from '../../src/schemes';
import { Messages } from '../../src/key/enums';
const { backend, key, PrivateKey, PublicKey } = require('../../src')
import { cartesian } from '../helpers';

const __labels = Object.values(Systems);
const __algorithms  = [...Object.values(Algorithms), undefined];


describe('plain encryption and decryption', () => {
  it.each(__labels)('over %s', async (label) => {
    const { privateKey, publicKey, ctx } = await key.generate(label);
    const message = (await ctx.randomPoint()).toBytes();
    const opts = { scheme: ElgamalSchemes.PLAIN };
    const { ciphertext } = await publicKey.encrypt(message, opts);
    const plaintext = await privateKey.decrypt(ciphertext, opts);
    expect(plaintext).toEqual(message);
  });
});


describe('plain encryption - invalid point encoding', () => {
  it.each(__labels)('over %s/%s', async (label) => {
    const { privateKey, publicKey, ctx } = await key.generate(label);
    const message = new Uint8Array([0, 1, 666, 999]);
    expect(publicKey.encrypt(message, { scheme: ElgamalSchemes.PLAIN })).rejects.toThrow(
      'Invalid point encoding'
    );
  });
});


describe('plain encryption proof - success without nonce', () => {
  it.each(cartesian([__labels, __algorithms]))('over %s/%s', async (label, algorithm) => {
    const { privateKey, publicKey, ctx } = await key.generate(label);
    const message = (await ctx.randomPoint()).toBytes();
    const { ciphertext, randomness } = await publicKey.encrypt(message, {
      scheme: ElgamalSchemes.PLAIN
    });
    const proof = await publicKey.proveEncryption(ciphertext, randomness, { algorithm });
    expect(proof.algorithm).toBe(algorithm || Algorithms.DEFAULT);
    const verified = await privateKey.verifyEncryption(ciphertext, proof);
    expect(verified).toBe(true);
  });
});


describe('plain encryption proof - success with nonce', () => {
  it.each(cartesian([__labels, __algorithms]))('over %s/%s', async (label, algorithm) => {
    const { privateKey, publicKey, ctx } = await key.generate(label);
    const message = (await ctx.randomPoint()).toBytes();
    const { ciphertext, randomness } = await publicKey.encrypt(message, {
      scheme: ElgamalSchemes.PLAIN
    });
    const nonce = await ctx.randomBytes();
    const proof = await publicKey.proveEncryption(ciphertext, randomness, { algorithm, nonce });
    expect(proof.algorithm).toBe(algorithm || Algorithms.DEFAULT);
    const verified = await privateKey.verifyEncryption(ciphertext, proof, { nonce });
    expect(verified).toBe(true);
  });
});


describe('plain encryption proof - failure if forged proof', () => {
  it.each(cartesian([__labels, __algorithms]))('over %s/%s', async (label, algorithm) => {
    const { privateKey, publicKey, ctx } = await key.generate(label);
    const message = (await ctx.randomPoint()).toBytes();
    const { ciphertext, randomness } = await publicKey.encrypt(message, {
      scheme: ElgamalSchemes.PLAIN
    });
    const proof = await publicKey.proveEncryption(ciphertext, randomness, { algorithm });
    proof.commitments[0] = await ctx.randomPoint();
    await expect(privateKey.verifyEncryption(ciphertext, proof)).rejects.toThrow(
      Messages.INVALID_ENCRYPTION_PROOF
    );
  });
});


describe('plain encryption proof - failure if wrong algorithm', () => {
  it.each(cartesian([__labels, __algorithms]))('over %s/%s', async (label, algorithm) => {
    const { privateKey, publicKey, ctx } = await key.generate(label);
    const message = (await ctx.randomPoint()).toBytes();
    const { ciphertext, randomness } = await publicKey.encrypt(message, {
      scheme: ElgamalSchemes.PLAIN
    });
    const proof = await publicKey.proveEncryption(ciphertext, randomness, { algorithm });
    proof.algorithm = (proof.algorithm == Algorithms.SHA256) ?
      Algorithms.SHA512 :
      Algorithms.SHA256;
    await expect(privateKey.verifyEncryption(ciphertext, proof)).rejects.toThrow(
      Messages.INVALID_ENCRYPTION_PROOF
    );
  });
});


describe('plain encryption proof - failure if missing nonce', () => {
  it.each(cartesian([__labels, __algorithms]))('over %s/%s', async (label, algorithm) => {
    const { privateKey, publicKey, ctx } = await key.generate(label);
    const message = (await ctx.randomPoint()).toBytes();
    const { ciphertext, randomness } = await publicKey.encrypt(message, {
      scheme: ElgamalSchemes.PLAIN
    });
    const nonce = await ctx.randomBytes();
    const proof = await publicKey.proveEncryption(ciphertext, randomness, { algorithm, nonce });
    await expect(privateKey.verifyEncryption(ciphertext, proof)).rejects.toThrow(
      Messages.INVALID_ENCRYPTION_PROOF
    );
  });
});


describe('plain encryption proof - failure if forged nonce', () => {
  it.each(cartesian([__labels, __algorithms]))('over %s/%s', async (label, algorithm) => {
    const { privateKey, publicKey, ctx } = await key.generate(label);
    const message = (await ctx.randomPoint()).toBytes();
    const { ciphertext, randomness } = await publicKey.encrypt(message, {
      scheme: ElgamalSchemes.PLAIN
    });
    const nonce = await ctx.randomBytes();
    const proof = await publicKey.proveEncryption(ciphertext, randomness, { algorithm, nonce });
    await expect(
      privateKey.verifyEncryption(ciphertext, proof, { nonce: await ctx.randomBytes() })
    ).rejects.toThrow(
      Messages.INVALID_ENCRYPTION_PROOF
    );
  });
});


describe('Decryptor generation', () => {
  it.each(__labels)('over %s', async (label) => {
    const { privateKey, publicKey, ctx } = await key.generate(label);
    const message = (await ctx.randomPoint()).toBytes();
    const { ciphertext, decryptor: expectedDecryptor } = await publicKey.encrypt(message, {
      scheme: ElgamalSchemes.PLAIN
    });
    const { decryptor, proof } = await privateKey.generateDecryptor(ciphertext, { noProof: false });
    expect(await decryptor.equals(expectedDecryptor)).toBe(true);
    expect(await publicKey.verifyDecryptor(ciphertext, decryptor, proof)).toBe(true);
  });
});


describe('Decryptor proof - success without nonce', () => {
  it.each(__labels)('over %s', async (label) => {
    const { privateKey, publicKey, ctx } = await key.generate(label);
    const message = (await ctx.randomPoint()).toBytes();
    const { ciphertext, decryptor } = await publicKey.encrypt(message, {
      scheme: ElgamalSchemes.PLAIN
    });
    const proof = await privateKey.proveDecryptor(ciphertext, decryptor);
    const verified = await publicKey.verifyDecryptor(ciphertext, decryptor, proof);
    expect(verified).toBe(true);
  });
});


describe('Decryptor proof - success with nonce', () => {
  it.each(cartesian([__labels, __algorithms]))('over %s/%s', async (label, algorithm) => {
    const { privateKey, publicKey, ctx } = await key.generate(label);
    const message = (await ctx.randomPoint()).toBytes();
    const { ciphertext, decryptor } = await publicKey.encrypt(message, {
      scheme: ElgamalSchemes.PLAIN
    });
    const nonce = await ctx.randomBytes();
    const proof = await privateKey.proveDecryptor(ciphertext, decryptor, { algorithm, nonce });
    expect(proof.algorithm).toBe(algorithm || Algorithms.DEFAULT);
    const verified = await publicKey.verifyDecryptor(ciphertext, decryptor, proof, { nonce });
    expect(verified).toBe(true);
  });
});


describe('Decryptor proof - failure if forged proof', () => {
  it.each(__labels)('over %s', async (label) => {
    const { privateKey, publicKey, ctx } = await key.generate(label);
    const message = (await ctx.randomPoint()).toBytes();
    const { ciphertext, decryptor } = await publicKey.encrypt(message, {
      scheme: ElgamalSchemes.PLAIN
    });
    const proof = await privateKey.proveDecryptor(ciphertext, decryptor);
    proof.commitments[0] = await ctx.randomPoint();
    await expect(publicKey.verifyDecryptor(ciphertext, decryptor, proof)).rejects.toThrow(
      Messages.INVALID_DECRYPTOR_PROOF
    );
  });
});


describe('Decryptor proof - failure if wrong algorithm', () => {
  it.each(cartesian([__labels, __algorithms]))('over %s/%s', async (label, algorithm) => {
    const { privateKey, publicKey, ctx } = await key.generate(label);
    const message = (await ctx.randomPoint()).toBytes();
    const { ciphertext, decryptor } = await publicKey.encrypt(message, {
      scheme: ElgamalSchemes.PLAIN
    });
    const proof = await privateKey.proveDecryptor(ciphertext, decryptor, { algorithm });
    proof.algorithm = (proof.algorithm == Algorithms.SHA256) ?
      Algorithms.SHA512 :
      Algorithms.SHA256;
    await expect(publicKey.verifyDecryptor(ciphertext, decryptor, proof)).rejects.toThrow(
      Messages.INVALID_DECRYPTOR_PROOF
    );
  });
});


describe('Decryptor proof - failure if missing nonce', () => {
  it.each(__labels)('over %s', async (label) => {
    const { privateKey, publicKey, ctx } = await key.generate(label);
    const message = (await ctx.randomPoint()).toBytes();
    const { ciphertext, decryptor } = await publicKey.encrypt(message, {
      scheme: ElgamalSchemes.PLAIN
    });
    const nonce = await ctx.randomBytes();
    const proof = await privateKey.proveDecryptor(ciphertext, decryptor, { nonce });
    await expect(publicKey.verifyDecryptor(ciphertext, decryptor, proof)).rejects.toThrow(
      Messages.INVALID_DECRYPTOR_PROOF
    );
  });
});


describe('Decryptor proof - failure if forged nonce', () => {
  it.each(__labels)('over %s', async (label) => {
    const { privateKey, publicKey, ctx } = await key.generate(label);
    const message = (await ctx.randomPoint()).toBytes();
    const { ciphertext, decryptor } = await publicKey.encrypt(message, {
      scheme: ElgamalSchemes.PLAIN
    });
    const nonce = await ctx.randomBytes();
    const proof = await privateKey.proveDecryptor(ciphertext, decryptor, { nonce });
    await expect(
      publicKey.verifyDecryptor(ciphertext, decryptor, proof, { nonce: await ctx.randomBytes() })
    ).rejects.toThrow(
      Messages.INVALID_DECRYPTOR_PROOF
    );
  });
});
