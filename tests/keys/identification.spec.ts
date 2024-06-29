import { Algorithms } from '../../src/enums';
import { initBackend, generateKey } from '../../src';
import { randomNonce } from '../../src/crypto';
import { cartesian } from '../utils';
import { resolveTestConfig } from '../environ';

const { systems, algorithms } = resolveTestConfig();


describe('Schnorr identification - success without nonce', () => {
  it.each(cartesian([systems, algorithms]))('over %s/%s', async (system, algorithm) => {
    const ctx = initBackend(system);
    const { privateKey, publicKey } = await generateKey(ctx);
    const proof = await privateKey.proveSecret({ algorithm });
    const verified = await publicKey.verifySecret(proof, { algorithm });
    expect(verified).toBe(true);
  });
});


describe('Schnorr identification - success with nonce', () => {
  it.each(systems)('over %s', async (system) => {
    const ctx = initBackend(system);
    const { privateKey, publicKey } = await generateKey(ctx);
    const nonce = await randomNonce();
    const proof = await privateKey.proveSecret({ nonce });
    const verified = await publicKey.verifySecret(proof, { nonce });
    expect(verified).toBe(true);
  });
});


describe('Schnorr identification - failure if forged proof', () => {
  it.each(systems)('over %s', async (system) => {
    const ctx = initBackend(system);
    const { privateKey, publicKey } = await generateKey(ctx);
    const proof = await privateKey.proveSecret();
    proof.commitment[0] = await ctx.randomPublic();
    await expect(publicKey.verifySecret(proof)).rejects.toThrow(
      'Invalid secret'
    );
  });
});


describe('Schnorr identification - failure if wrong algorithm', () => {
  it.each(cartesian([systems, algorithms]))('over %s/%s', async (system, algorithm) => {
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
      'Invalid secret'
    );
  });
});


describe('Schnorr identification - failure if missing nonce', () => {
  it.each(systems)('over %s', async (system) => {
    const ctx = initBackend(system);
    const { privateKey, publicKey } = await generateKey(ctx);
    const nonce = await randomNonce();
    const proof = await privateKey.proveSecret({ nonce });
    await expect(publicKey.verifySecret(proof)).rejects.toThrow(
      'Invalid secret'
    );
  });
});


describe('Schnorr identification - failure if forged nonce', () => {
  it.each(systems)('over %s', async (system) => {
    const ctx = initBackend(system);
    const { privateKey, publicKey } = await generateKey(ctx);
    const nonce = await randomNonce();
    const proof = await privateKey.proveSecret({ nonce });
    await expect(
      publicKey.verifySecret(proof, { nonce: await randomNonce() })
    ).rejects.toThrow(
      'Invalid secret'
    );
  });
});
