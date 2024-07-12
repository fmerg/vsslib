import { Algorithms } from 'vsslib/enums';
import { initBackend, generateKey } from 'vsslib';
import { randomNonce } from 'vsslib/crypto';
import { cartesian } from '../utils';
import { resolveTestConfig } from '../environ';

const { systems, algorithms } = resolveTestConfig();


describe('Schnorr identification', () => {
  it.each(cartesian([systems, algorithms]))(
    'success - without nonce - over %s/%s', async (system, algorithm) => {
    const ctx = initBackend(system);
    const { privateKey, publicKey } = await generateKey(ctx);
    const proof = await privateKey.proveSecret({ algorithm });
    const isValid = await publicKey.verifySecret(proof, { algorithm });
    expect(isValid).toBe(true);
  });
  it.each(systems)('success - with nonce - over %s', async (system) => {
    const ctx = initBackend(system);
    const { privateKey, publicKey } = await generateKey(ctx);
    const nonce = await randomNonce();
    const proof = await privateKey.proveSecret({ nonce });
    const isValid = await publicKey.verifySecret(proof, { nonce });
    expect(isValid).toBe(true);
  });
  it.each(systems)('failure - forged proof - over %s', async (system) => {
    const ctx = initBackend(system);
    const { privateKey, publicKey } = await generateKey(ctx);
    const proof = await privateKey.proveSecret();
    proof.commitment[0] = await ctx.randomPublic();
    await expect(publicKey.verifySecret(proof)).rejects.toThrow(
      'Invalid Schnorr proof'
    );
  });
  it.each(systems)('failure - forged nonce - over %s', async (system) => {
    const ctx = initBackend(system);
    const { privateKey, publicKey } = await generateKey(ctx);
    const nonce = await randomNonce();
    const proof = await privateKey.proveSecret({ nonce });
    await expect(
      publicKey.verifySecret(proof, { nonce: await randomNonce() })
    ).rejects.toThrow(
      'Invalid Schnorr proof'
    );
  });
  it.each(systems)('failure - missing nonce - over %s', async (system) => {
    const ctx = initBackend(system);
    const { privateKey, publicKey } = await generateKey(ctx);
    const nonce = await randomNonce();
    const proof = await privateKey.proveSecret({ nonce });
    await expect(publicKey.verifySecret(proof)).rejects.toThrow(
      'Invalid Schnorr proof'
    );
  });
  it.each(cartesian([systems, algorithms]))(
    'failure - wrong algorithm - over %s/%s', async (system, algorithm) => {
    const ctx = initBackend(system);
    const { privateKey, publicKey } = await generateKey(ctx);
    const proof = await privateKey.proveSecret({ algorithm });
    await expect(
      publicKey.verifySecret(proof, {
        algorithm: algorithm == Algorithms.SHA256 ?
          Algorithms.SHA512 :
          Algorithms.SHA256
      })
    ).rejects.toThrow(
      'Invalid Schnorr proof'
    );
  });
});
