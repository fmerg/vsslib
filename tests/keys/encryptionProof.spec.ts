import { Algorithms, ElgamalSchemes } from 'vsslib/enums';
import { initBackend } from 'vsslib/backend';
import { generateKey } from 'vsslib/keys';
import { randomPublic } from 'vsslib/secrets';
import { randomNonce } from 'vsslib/crypto';
import { cartesian, isEqualBuffer } from '../utils';
import { buildMessage } from '../helpers';
import { resolveTestConfig } from '../environ';

const { systems, elgamalSchemes: schemes, modes, algorithms } = resolveTestConfig();


describe('Unified encrypt-then-prove', () => {
  it.each(cartesian([systems, schemes, algorithms]))(
    'success - without nonce - over %s/%s/%s', async (system, scheme, algorithm) => {
    const ctx = initBackend(system);
    const { privateKey, publicKey } = await generateKey(ctx);
    const message = await buildMessage(ctx, scheme);
    const opts = { scheme, verAlgorithm: algorithm };
    const { ciphertext, proof } = await publicKey.encryptProve(message, opts)
    const { plaintext } = await privateKey.verifyDecrypt(ciphertext, proof, opts)
    expect(isEqualBuffer(plaintext, message)).toBe(true);
  });
  it.each(cartesian([systems, schemes, algorithms]))(
    'success - with nonce - over %s/%s/%s', async (system, scheme, algorithm) => {
    const ctx = initBackend(system);
    const { privateKey, publicKey } = await generateKey(ctx);
    const message = await buildMessage(ctx, scheme);
    const opts = { scheme, verAlgorithm: algorithm, nonce: randomNonce() };
    const { ciphertext, proof } = await publicKey.encryptProve(message, opts)
    const { plaintext } = await privateKey.verifyDecrypt(ciphertext, proof, opts)
    expect(isEqualBuffer(plaintext, message)).toBe(true);
  });
  it.each(cartesian([systems, schemes, algorithms]))(
    'failure - forged proof - over %s/%s/%s', async (system, scheme, algorithm) => {
    const ctx = initBackend(system);
    const { privateKey, publicKey } = await generateKey(ctx);
    const message = await buildMessage(ctx, scheme);
    const opts = { scheme, verAlgorithm: algorithm };
    const { ciphertext, proof } = await publicKey.encryptProve(message, opts)
    proof.commitment[0] = await randomPublic(ctx);
    await expect(
      privateKey.verifyDecrypt(ciphertext, proof, opts)
    ).rejects.toThrow(
      'Invalid encryption'
    );
  });
  it.each(cartesian([systems, schemes, algorithms]))(
    'failure - forged nonce - over %s/%s/%s', async (system, scheme, algorithm) => {
    const ctx = initBackend(system);
    const { privateKey, publicKey } = await generateKey(ctx);
    const message = await buildMessage(ctx, scheme);
    const opts = { scheme, verAlgorithm: algorithm, nonce: randomNonce() };
    const { ciphertext, proof } = await publicKey.encryptProve(message, opts)
    const { plaintext } = await privateKey.verifyDecrypt(ciphertext, proof, opts)
    await expect(
      privateKey.verifyDecrypt(ciphertext, proof, { ...opts, nonce: await randomNonce() })
    ).rejects.toThrow(
      'Invalid encryption'
    );
  });
  it.each(cartesian([systems, schemes, algorithms]))(
    'failure - missing nonce - over %s/%s/%s', async (system, scheme, algorithm) => {
    const ctx = initBackend(system);
    const { privateKey, publicKey } = await generateKey(ctx);
    const message = await buildMessage(ctx, scheme);
    const opts = { scheme, verAlgorithm: algorithm, nonce: randomNonce() };
    const { ciphertext, proof } = await publicKey.encryptProve(message, opts)
    const { plaintext } = await privateKey.verifyDecrypt(ciphertext, proof, opts)
    await expect(
      privateKey.verifyDecrypt(ciphertext, proof, {
        scheme: opts.scheme,
        verAlgorithm: opts.verAlgorithm
      })
    ).rejects.toThrow(
      'Invalid encryption'
    );
  });
  it.each(cartesian([systems, schemes, algorithms]))(
    'failure - wrong algorithm - over %s/%s/%s', async (system, scheme, algorithm) => {
    const ctx = initBackend(system);
    const { privateKey, publicKey } = await generateKey(ctx);
    const message = await buildMessage(ctx, scheme);
    const opts = { scheme, verAlgorithm: algorithm };
    const { ciphertext, proof } = await publicKey.encryptProve(message, opts)
    await expect(
      privateKey.verifyDecrypt(ciphertext, proof, {
        ...opts,
        verAlgorithm: algorithm == Algorithms.SHA256 ?
          Algorithms.SHA512 :
          Algorithms.SHA256
      })
    ).rejects.toThrow(
      'Invalid encryption'
    );
  });
});


describe('Standalone proof-of-encryption', () => {
  it.each(cartesian([systems, schemes, algorithms]))(
    'success - without nonce - over %s/%s/%s', async (system, scheme, algorithm) => {
    const ctx = initBackend(system);
    const { privateKey, publicKey } = await generateKey(ctx);
    const message = await buildMessage(ctx, scheme);
    const { ciphertext, randomness } = await publicKey.encrypt(message, { scheme });
    const proof = await publicKey.proveEncryption(ciphertext, randomness, { algorithm });
    const isValid = await privateKey.verifyEncryption(ciphertext, proof, { algorithm });
    expect(isValid).toBe(true);
  });
  it.each(cartesian([systems, schemes, algorithms]))(
    'success - with nonce - over %s/%s/%s', async (system, scheme, algorithm) => {
    const ctx = initBackend(system);
    const { privateKey, publicKey } = await generateKey(ctx);
    const message = await buildMessage(ctx, scheme);
    const { ciphertext, randomness } = await publicKey.encrypt(message, { scheme });
    const nonce = await randomNonce();
    const proof = await publicKey.proveEncryption(ciphertext, randomness, { algorithm, nonce });
    const isValid = await privateKey.verifyEncryption(ciphertext, proof, { algorithm, nonce });
    expect(isValid).toBe(true);
  });
  it.each(cartesian([systems, schemes, algorithms]))(
    'failure - forged proof - over %s/%s/%s', async (system, scheme, algorithm) => {
    const ctx = initBackend(system);
    const { privateKey, publicKey } = await generateKey(ctx);
    const message = await buildMessage(ctx, scheme);
    const { ciphertext, randomness } = await publicKey.encrypt(message, { scheme });
    const proof = await publicKey.proveEncryption(ciphertext, randomness, { algorithm });
    proof.commitment[0] = await randomPublic(ctx);
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
