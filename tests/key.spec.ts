import { Algorithms, Systems } from '../src/enums';
import { Messages } from '../src/key/enums';
import { Algorithm } from '../src/types';
const { backend, key, PrivateKey, PublicKey } = require('../src')

const __labels = Object.values(Systems);


describe('Key generation', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const { privateKey, publicKey } = await key.generate(label);
    const private1 = await PrivateKey.fromScalar(ctx, privateKey.scalar);
    const private2 = await PrivateKey.fromBytes(ctx, privateKey.bytes);
    expect(await private1.isEqual(privateKey)).toBe(true);
    expect(await private2.isEqual(privateKey)).toBe(true);
    const public1 = await PublicKey.fromPoint(ctx, publicKey.point);
    expect(await public1.isEqual(publicKey)).toBe(true);
  });
});


describe('Key serialization and deserialization', () => {
  it.each(__labels)('over %s', async (label) => {
    const { privateKey, publicKey } = await key.generate(label);

    // Private counterpart
    const privSerialized = privateKey.serialize();
    expect(privSerialized).toEqual({
      value: Buffer.from(privateKey.bytes).toString('hex'),
      system: privateKey.ctx.label,
    });
    const privateBack = await PrivateKey.deserialize(privSerialized);
    expect(await privateBack.isEqual(privateKey)).toBe(true);

    // Public counterpart
    const pubSerialized = publicKey.serialize();
    expect(pubSerialized).toEqual({
      value: Buffer.from(publicKey.bytes).toString('hex'),
      system: publicKey.ctx.label,
    });
    const publicBack = await PublicKey.deserialize(pubSerialized);
    expect(await publicBack.isEqual(publicKey)).toBe(true);
  });
});


describe('Public key extraction', () => {
  it.each(__labels)('over %s', async (label) => {
    const { privateKey, publicKey } = await key.generate(label);
    expect(await publicKey.ctx.isEqual(privateKey.ctx)).toBe(true);
    expect(await publicKey.point.isEqual(await privateKey.publicPoint()));
  });
});


describe('Diffie-Hellman handshake', () => {
  it.each(__labels)('over %s', async (label) => {
    const { privateKey: private1, publicKey: public1 } = await key.generate(label);
    const { privateKey: private2, publicKey: public2 } = await key.generate(label);
    const point1 = await private1.diffieHellman(public2);
    const point2 = await private2.diffieHellman(public1);
    const expected = await private1.ctx.operate(private1.scalar, public2.point);
    expect(await point1.isEqual(expected)).toBe(true);
    expect(await point2.isEqual(point1)).toBe(true);
  });
});


describe('Identity proof - success', () => {
  it.each(__labels)('over %s', async (label) => {
    const { privateKey, publicKey } = await key.generate(label);
    const proof = await privateKey.proveIdentity();
    const verified = await publicKey.verifyIdentity(proof);
    expect(verified).toBe(true);
  });
});


describe('Identity proof - failure if tampered proof', () => {
  it.each(__labels)('over %s', async (label) => {
    const { privateKey, publicKey } = await key.generate(label);
    const proof = await privateKey.proveIdentity();
    proof.commitments[0] = await privateKey.ctx.randomPoint();
    await expect(publicKey.verifyIdentity(proof)).rejects.toThrow(
      Messages.INVALID_IDENTITY_PROOF
    );
  });
});


describe('Identity proof - failure if wrong algorithm', () => {
  it.each(__labels)('over %s', async (label) => {
    const { privateKey, publicKey } = await key.generate(label);
    const proof = await privateKey.proveIdentity();
    proof.algorithm = (proof.algorithm == Algorithms.SHA256) ?
      Algorithms.SHA512 :
      Algorithms.SHA256;
    await expect(publicKey.verifyIdentity(proof)).rejects.toThrow(
      Messages.INVALID_IDENTITY_PROOF
    );
  });
});


describe('Elgamal encryption and decryption', () => {
  it.each(__labels)('over %s', async (label) => {
    const { privateKey, publicKey } = await key.generate(label);
    const message = await privateKey.ctx.randomPoint();
    const { ciphertext } = await publicKey.encrypt(message);
    const plaintext = await privateKey.decrypt(ciphertext);
    expect(await plaintext.isEqual(message)).toBe(true);
  });
});


describe('Elgamal encryption proof - success', () => {
  it.each(__labels)('over %s', async (label) => {
    const { privateKey, publicKey } = await key.generate(label);
    const message = await privateKey.ctx.randomPoint();
    const { ciphertext, randomness } = await publicKey.encrypt(message);
    const proof = await publicKey.proveEncryption(ciphertext, randomness);
    const verified = await privateKey.verifyEncryption(ciphertext, proof);
    expect(verified).toBe(true);
  });
});


describe('Elgamal encryption proof - failure if tampered proof', () => {
  it.each(__labels)('over %s', async (label) => {
    const { privateKey, publicKey } = await key.generate(label);
    const message = await privateKey.ctx.randomPoint();
    const { ciphertext, randomness } = await publicKey.encrypt(message);
    const proof = await publicKey.proveEncryption(ciphertext, randomness);
    // Tamper commitments
    proof.commitments[0] = await publicKey.ctx.randomPoint();
    await expect(privateKey.verifyEncryption(ciphertext, proof)).rejects.toThrow(
      Messages.INVALID_ENCRYPTION_PROOF
    );
  });
});


describe('Elgamal encryption proof - failure if wrong algorithm', () => {
  it.each(__labels)('over %s', async (label) => {
    const { privateKey, publicKey } = await key.generate(label);
    const message = await privateKey.ctx.randomPoint();
    const { ciphertext, randomness } = await publicKey.encrypt(message);
    const proof = await publicKey.proveEncryption(ciphertext, randomness);
    // Tamper algorithm
    proof.algorithm = (proof.algorithm == Algorithms.SHA256) ?
      Algorithms.SHA512 :
      Algorithms.SHA256;
    await expect(privateKey.verifyEncryption(ciphertext, proof)).rejects.toThrow(
      Messages.INVALID_ENCRYPTION_PROOF
    );
  });
});


describe('Decryptor proof - success', () => {
  it.each(__labels)('over %s', async (label) => {
    const { privateKey, publicKey } = await key.generate(label);
    const message = await privateKey.ctx.randomPoint();
    const { ciphertext, decryptor } = await publicKey.encrypt(message);
    const proof = await privateKey.proveDecryptor(ciphertext, decryptor);
    const verified = await publicKey.verifyDecryptor(ciphertext, decryptor, proof);
    expect(verified).toBe(true);
  });
});


describe('Decryptor proof - failure if tampered proof', () => {
  it.each(__labels)('over %s', async (label) => {
    const { privateKey, publicKey } = await key.generate(label);
    const message = await privateKey.ctx.randomPoint();
    const { ciphertext, decryptor } = await publicKey.encrypt(message);
    const proof = await privateKey.proveDecryptor(ciphertext, decryptor);
    // Tamper commitments
    proof.commitments[0] = await publicKey.ctx.randomPoint();
    await expect(publicKey.verifyDecryptor(ciphertext, decryptor, proof)).rejects.toThrow(
      Messages.INVALID_DECRYPTOR_PROOF
    );
  });
});


describe('Decryptor proof - failure if wrong algorithm', () => {
  it.each(__labels)('over %s', async (label) => {
    const { privateKey, publicKey } = await key.generate(label);
    const message = await privateKey.ctx.randomPoint();
    const { ciphertext, decryptor } = await publicKey.encrypt(message);
    const proof = await privateKey.proveDecryptor(ciphertext, decryptor);
    // Tamper algorithm
    proof.algorithm = (proof.algorithm == Algorithms.SHA256) ?
      Algorithms.SHA512 :
      Algorithms.SHA256;
    await expect(publicKey.verifyDecryptor(ciphertext, decryptor, proof)).rejects.toThrow(
      Messages.INVALID_DECRYPTOR_PROOF
    );
  });
});

