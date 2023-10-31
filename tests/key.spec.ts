import { Algorithms, Systems } from '../src/enums';
import { Messages } from '../src/key/enums';
import { Algorithm } from '../src/types';
const { backend, key, PrivateKey, PublicKey } = require('../src')

const __labels = Object.values(Systems);


describe('construct key', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);

    const priv1 = await key.generate(label);
    const priv2 = new PrivateKey(ctx, priv1.secret, priv1.seed);
    expect(await priv1.isEqual(priv2)).toBe(true);

    const point1 = await priv1.publicPoint();
    const point2 = await priv2.publicPoint();
    expect(await point2.isEqual(point1)).toBe(true);

    const pub1 = await priv1.publicKey();
    const pub2 = await priv2.publicKey();
    expect(await pub2.isEqual(pub1)).toBe(true);
  });
});


describe('extract public', () => {
  it.each(__labels)('over %s', async (label) => {
    const priv = await key.generate(label);
    const pub = await priv.publicKey();
    expect(await pub.ctx.isEqual(priv.ctx)).toBe(true);
    expect(await pub.point.isEqual(await priv.publicPoint()));
  });
});


describe('serialize key', () => {
  it.each(__labels)('over %s', async (label) => {
    const priv = await key.generate(label);
    const serialized = priv.serialize();
    const privBack = key.deserialize(serialized);
    expect(await privBack.isEqual(priv)).toBe(true);
  });
});


describe('serialize public', () => {
  it.each(__labels)('over %s', async (label) => {
    const priv = await key.generate(label);
    const pub = await priv.publicKey();
    const serialized = pub.serialize()
    const pubBack = key.deserialize(serialized);
    expect(await pubBack.isEqual(pub)).toBe(true);
  });
});


describe('diffie-hellman', () => {
  it.each(__labels)('over %s', async (label) => {
    const priv1 = await key.generate(label);
    const pub1 = await priv1.publicKey();

    const priv2 = await key.generate(label);
    const pub2 = await priv2.publicKey();

    const pt1 = await priv1.diffieHellman(pub2);
    const pt2 = await priv2.diffieHellman(pub1);

    expect(await pt1.isEqual(pt2)).toBe(true);
  });
});


describe('identity proof - success', () => {
  it.each(__labels)('over %s', async (label) => {
    const priv = await key.generate(label);
    const pub = await priv.publicKey();
    const proof = await priv.proveIdentity();
    const verified = await pub.verifyIdentity(proof);
    expect(verified).toBe(true);
  });
});


describe('identity proof - failure if tampered proof', () => {
  it.each(__labels)('over %s', async (label) => {
    const priv = await key.generate(label);
    const pub = await priv.publicKey();
    const proof = await priv.proveIdentity();
    proof.commitments[0] = await priv.ctx.randomPoint();
    await expect(pub.verifyIdentity(proof)).rejects.toThrow(
      Messages.INVALID_IDENTITY_PROOF
    );
  });
});


describe('identity proof - failure if wrong algorithm', () => {
  it.each(__labels)('over %s', async (label) => {
    const priv = await key.generate(label);
    const pub = await priv.publicKey();
    const proof = await priv.proveIdentity();
    proof.algorithm = (proof.algorithm == Algorithms.SHA256) ?
      Algorithms.SHA512 :
      Algorithms.SHA256;
    await expect(pub.verifyIdentity(proof)).rejects.toThrow(
      Messages.INVALID_IDENTITY_PROOF
    );
  });
});


describe('encryption and decryption', () => {
  it.each(__labels)('over %s', async (label) => {
    const priv = await key.generate(label);
    const pub = await priv.publicKey();
    const message = await priv.ctx.randomPoint();
    const { ciphertext } = await pub.encrypt(message);
    const plaintext = await priv.decrypt(ciphertext);
    expect(await plaintext.isEqual(message)).toBe(true);
  });
});


describe('encryption proof - success', () => {
  it.each(__labels)('over %s', async (label) => {
    const priv = await key.generate(label);
    const pub = await priv.publicKey();
    const message = await priv.ctx.randomPoint();
    const { ciphertext, randomness, decryptor } = await pub.encrypt(message);
    const proof = await pub.proveEncryption(ciphertext, randomness);
    const verified = await priv.verifyEncryption(ciphertext, proof);
    expect(verified).toBe(true);
  });
});


describe('encryption proof - failure if tampered proof', () => {
  it.each(__labels)('over %s', async (label) => {
    const priv = await key.generate(label);
    const pub = await priv.publicKey();
    const message = await priv.ctx.randomPoint();
    const { ciphertext, randomness, decryptor } = await pub.encrypt(message);
    const proof = await pub.proveEncryption(ciphertext, randomness);
    // Tamper commitments
    proof.commitments[0] = await pub.ctx.randomPoint();
    await expect(priv.verifyEncryption(ciphertext, proof)).rejects.toThrow(
      Messages.INVALID_ENCRYPTION_PROOF
    );
  });
});


describe('encryption proof - failure if wrong algorithm', () => {
  it.each(__labels)('over %s', async (label) => {
    const priv = await key.generate(label);
    const pub = await priv.publicKey();
    const message = await priv.ctx.randomPoint();
    const { ciphertext, randomness, decryptor } = await pub.encrypt(message);
    const proof = await pub.proveEncryption(ciphertext, randomness);
    // Tamper algorithm
    proof.algorithm = (proof.algorithm == Algorithms.SHA256) ?
      Algorithms.SHA512 :
      Algorithms.SHA256;
    await expect(priv.verifyEncryption(ciphertext, proof)).rejects.toThrow(
      Messages.INVALID_ENCRYPTION_PROOF
    );
  });
});


describe('decryptor proof - success', () => {
  it.each(__labels)('over %s', async (label) => {
    const priv = await key.generate(label);
    const pub = await priv.publicKey();
    const message = await priv.ctx.randomPoint();
    const { ciphertext, randomness, decryptor } = await pub.encrypt(message);
    const proof = await priv.proveDecryptor(ciphertext, decryptor);
    const verified = await pub.verifyDecryptor(ciphertext, decryptor, proof);
    expect(verified).toBe(true);
  });
});


describe('decryptor proof - failure if tampered proof', () => {
  it.each(__labels)('over %s', async (label) => {
    const priv = await key.generate(label);
    const pub = await priv.publicKey();
    const message = await priv.ctx.randomPoint();
    const { ciphertext, randomness, decryptor } = await pub.encrypt(message);
    const proof = await priv.proveDecryptor(ciphertext, decryptor);
    // Tamper commitments
    proof.commitments[0] = await pub.ctx.randomPoint();
    await expect(pub.verifyDecryptor(ciphertext, decryptor, proof)).rejects.toThrow(
      Messages.INVALID_DECRYPTOR_PROOF
    );
  });
});


describe('decryptor proof - failure if wrong algorithm', () => {
  it.each(__labels)('over %s', async (label) => {
    const priv = await key.generate(label);
    const pub = await priv.publicKey();
    const message = await priv.ctx.randomPoint();
    const { ciphertext, randomness, decryptor } = await pub.encrypt(message);
    const proof = await priv.proveDecryptor(ciphertext, decryptor);
    // Tamper algorithm
    proof.algorithm = (proof.algorithm == Algorithms.SHA256) ?
      Algorithms.SHA512 :
      Algorithms.SHA256;
    await expect(pub.verifyDecryptor(ciphertext, decryptor, proof)).rejects.toThrow(
      Messages.INVALID_DECRYPTOR_PROOF
    );
  });
});

