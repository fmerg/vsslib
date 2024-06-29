import { initBackend } from '../../src/backend';
import { PrivateKeyShare } from '../../src/keys/shares';
import { Algorithms } from '../../src/enums';
import { System, ElgamalScheme, Algorithm } from '../../src/types';
import { generateKey } from '../../src';
import { randomNonce } from '../../src/crypto';
import { cartesian } from '../utils';
import { mockMessage } from '../helpers';
import { resolveTestConfig } from '../environ';

const createPartialDecryptorSetup = async (opts: {
  system: System, scheme: ElgamalScheme, algorithm: Algorithm, nonce?: Uint8Array
}) => {
  const { system, scheme, algorithm, nonce } = opts;
  const ctx = initBackend(system);
  const privateKey = new PrivateKeyShare(ctx, await ctx.randomSecret(), 666);
  const publicKey = await privateKey.getPublicShare();
  const message = await mockMessage(ctx, scheme);
  const { ciphertext } = await publicKey.encrypt(message, { scheme });
  const decryptor = await privateKey.computePartialDecryptor(ciphertext, { algorithm, nonce })
  return {
    ctx,
    privateKey,
    publicKey,
    message,
    ciphertext,
    decryptor,
  }
}


const { systems, elgamalSchemes: schemes, modes, algorithms } = resolveTestConfig();

describe('success - no nonce', () => {
  it.each(
    cartesian([systems, schemes, algorithms])
  )('over %s/%s/%s', async (system, scheme, algorithm) => {
    const { publicKey, ciphertext, decryptor } = await createPartialDecryptorSetup({
      system, scheme, algorithm
    });
    const verified = await publicKey.verifyPartialDecryptor(ciphertext, decryptor, { algorithm });
    expect(verified).toBe(true);
  });
});

describe('success - with nonce', () => {
  it.each(
    cartesian([systems, schemes, algorithms])
  )('over %s/%s/%s', async (system, scheme, algorithm) => {
    const nonce = await randomNonce();
    const { publicKey, ciphertext, decryptor } = await createPartialDecryptorSetup({
      system, scheme, algorithm, nonce
    });
    const verified = await publicKey.verifyPartialDecryptor(ciphertext, decryptor, {
      algorithm, nonce
    });
    expect(verified).toBe(true);
  });
});


describe('failure - forged proof', () => {
  it.each(
    cartesian([systems, schemes, algorithms])
  )('over %s/%s/%s', async (system, scheme, algorithm) => {
    const { ctx, publicKey, ciphertext, decryptor } = await createPartialDecryptorSetup({
      system, scheme, algorithm
    });
    decryptor.proof.commitment[0] = (await ctx.randomPoint()).toBytes();
    await expect(
      publicKey.verifyPartialDecryptor(ciphertext, decryptor, { algorithm })
    ).rejects.toThrow(
      'Invalid partial decryptor'
    );
  });
});


describe('failure - wrong algorithm', () => {
  it.each(
    cartesian([systems, schemes, algorithms])
  )('over %s/%s/%s', async (system, scheme, algorithm) => {
    const { publicKey, ciphertext, decryptor } = await createPartialDecryptorSetup({
      system, scheme, algorithm
    });
    await expect(
      publicKey.verifyPartialDecryptor(
        ciphertext,
        decryptor,
        {
          algorithm: algorithm == Algorithms.SHA256 ?
            Algorithms.SHA512 :
            Algorithms.SHA256
        })
    ).rejects.toThrow(
      'Invalid partial decryptor'
    );
  });
});


describe('failure - missing nonce', () => {
  it.each(
    cartesian([systems, schemes, algorithms])
  )('over %s/%s/%s', async (system, scheme, algorithm) => {
    const nonce = await randomNonce();
    const { publicKey, ciphertext, decryptor } = await createPartialDecryptorSetup({
      system, scheme, algorithm, nonce
    });
    await expect(
      publicKey.verifyPartialDecryptor(ciphertext, decryptor, { algorithm })
    ).rejects.toThrow(
      'Invalid partial decryptor'
    );
  });
});


describe('failure - forged nonce', () => {
  it.each(
    cartesian([systems, schemes, algorithms])
  )('over %s/%s/%s', async (system, scheme, algorithm) => {
    const nonce = await randomNonce();
    const { publicKey, ciphertext, decryptor } = await createPartialDecryptorSetup({
      system, scheme, algorithm, nonce
    });
    await expect(
      publicKey.verifyPartialDecryptor(ciphertext, decryptor, {
        algorithm,
        nonce: await randomNonce(),
      })
    ).rejects.toThrow(
      'Invalid partial decryptor'
    );
  });
});
