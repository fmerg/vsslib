import { Algorithms, ElgamalSchemes } from '../../src/enums';
import { initBackend, generateKey } from '../../src';
import { randomNonce } from '../../src/crypto';
import { cartesian } from '../utils';
import { buildMessage } from '../helpers';
import { resolveTestConfig } from '../environ';

const { systems, elgamalSchemes: schemes, modes, algorithms } = resolveTestConfig();


describe('Elgamal encryption', () => {
  it.each(cartesian([systems, schemes, modes, algorithms]))('over %s/%s/%s/%s', async (
    system, scheme, mode, algorithm
  ) => {
    const ctx = initBackend(system);
    const { privateKey, publicKey } = await generateKey(ctx);
    const message = await buildMessage(ctx, scheme);
    const opts = { scheme, mode, algorithm };
    const { ciphertext } = await publicKey.encrypt(message, opts);
    const plaintext = await privateKey.decrypt(ciphertext, opts);
    expect(plaintext).toEqual(message);
  });
});


describe('Elgamal plain encryption - invalid point encoding', () => {
  it.each(systems)('over %s', async (system) => {
    const ctx = initBackend(system);
    const { privateKey, publicKey } = await generateKey(ctx);
    const message = new Uint8Array([0, 1, 666, 999]);
    expect(publicKey.encrypt(message, { scheme: ElgamalSchemes.PLAIN })).rejects.toThrow(
      'bad encoding:'
    );
  });
});


describe('Encrypt-then-prove', () => {
  it.each(cartesian([systems, schemes, algorithms]))(
    'success - without nonce - over %s/%s/%s', async (system, scheme, algorithm) => {
    const ctx = initBackend(system);
    const { privateKey, publicKey } = await generateKey(ctx);
    const message = await buildMessage(ctx, scheme);
    const { ciphertext, randomness } = await publicKey.encrypt(message, { scheme });
    const proof = await publicKey.proveEncryption(ciphertext, randomness, { algorithm });
    const verified = await privateKey.verifyEncryption(ciphertext, proof, { algorithm });
    expect(verified).toBe(true);
  });
  it.each(cartesian([systems, schemes, algorithms]))(
    'success - with nonce - over %s/%s/%s', async (system, scheme, algorithm) => {
    const ctx = initBackend(system);
    const { privateKey, publicKey } = await generateKey(ctx);
    const message = await buildMessage(ctx, scheme);
    const { ciphertext, randomness } = await publicKey.encrypt(message, { scheme });
    const nonce = await randomNonce();
    const proof = await publicKey.proveEncryption(ciphertext, randomness, { algorithm, nonce });
    const verified = await privateKey.verifyEncryption(ciphertext, proof, { algorithm, nonce });
    expect(verified).toBe(true);
  });
  it.each(cartesian([systems, schemes, algorithms]))(
    'failure - forged proof - over %s/%s/%s', async (system, scheme, algorithm) => {
    const ctx = initBackend(system);
    const { privateKey, publicKey } = await generateKey(ctx);
    const message = await buildMessage(ctx, scheme);
    const { ciphertext, randomness } = await publicKey.encrypt(message, { scheme });
    const proof = await publicKey.proveEncryption(ciphertext, randomness, { algorithm });
    proof.commitment[0] = await ctx.randomPublic();
    await expect(privateKey.verifyEncryption(ciphertext, proof)).rejects.toThrow(
      'Invalid encryption'
    );
  });
  it.each(cartesian([systems, schemes, algorithms]))(
    'failure - forged nonce - over %s/%s/%s', async (system, scheme, algorithm) => {
    const ctx = initBackend(system);
    const { privateKey, publicKey } = await generateKey(ctx);
    const message = await buildMessage(ctx, scheme);
    const { ciphertext, randomness } = await publicKey.encrypt(message, { scheme });
    const nonce = await randomNonce();
    const proof = await publicKey.proveEncryption(ciphertext, randomness, { algorithm, nonce });
    await expect(
      privateKey.verifyEncryption(ciphertext, proof, { nonce: await randomNonce() })
    ).rejects.toThrow(
      'Invalid encryption'
    );
  });
  it.each(cartesian([systems, schemes, algorithms]))(
    'failure - missing nonce - over %s/%s/%s', async (system, scheme, algorithm) => {
    const ctx = initBackend(system);
    const { privateKey, publicKey } = await generateKey(ctx);
    const message = await buildMessage(ctx, scheme);
    const { ciphertext, randomness } = await publicKey.encrypt(message, { scheme });
    const nonce = await randomNonce();
    const proof = await publicKey.proveEncryption(ciphertext, randomness, { algorithm, nonce });
    await expect(privateKey.verifyEncryption(ciphertext, proof, { algorithm })).rejects.toThrow(
      'Invalid encryption'
    );
  });
  it.each(cartesian([systems, schemes, algorithms]))(
    'failure - wrong algorithm - over %s/%s/%s', async (system, scheme, algorithm) => {
    const ctx = initBackend(system);
    const { privateKey, publicKey } = await generateKey(ctx);
    const message = await buildMessage(ctx, scheme);
    const { ciphertext, randomness } = await publicKey.encrypt(message, { scheme });
    const proof = await publicKey.proveEncryption(ciphertext, randomness, { algorithm });
    await expect(
      privateKey.verifyEncryption(ciphertext, proof, {
        algorithm: algorithm == Algorithms.SHA256 ?
          Algorithms.SHA512 :
          Algorithms.SHA256
      })
    ).rejects.toThrow(
      'Invalid encryption'
    );
  });
});
