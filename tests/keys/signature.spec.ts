import { Algorithms, SignatureSchemes } from '../../src/enums';
import { Algorithm } from '../../src/types';
import { initBackend, generateKey } from '../../src';
import { randomNonce } from '../../src/crypto';
import { cartesian } from '../utils';
import { resolveTestConfig } from '../environ';

let { systems, algorithms, signatureSchemes: schemes } = resolveTestConfig();

algorithms  = [...algorithms, undefined];


describe('Signing and verification', () => {
  it.each(cartesian([systems, schemes, algorithms]))(
    'success - without nonce -over %s/%s/%s', async (system, scheme, algorithm) => {
    const ctx = initBackend(system);
    const { privateKey, publicKey } = await generateKey(ctx);
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const signature = await privateKey.signMessage(message, { scheme, algorithm });
    const verified = await publicKey.verifySignature(
      message, signature, {
        scheme,
        algorithm
      }
    );
    expect(verified).toBe(true);
  });
  it.each(cartesian([systems, schemes, algorithms]))(
    'success - with nonce - over %s/%s/%s', async (system, scheme, algorithm) => {
    const ctx = initBackend(system);
    const { privateKey, publicKey } = await generateKey(ctx);
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const nonce = await randomNonce();
    const signature = await privateKey.signMessage(message, { scheme, algorithm, nonce });
    const verified = await publicKey.verifySignature(
      message, signature, {
        scheme,
        algorithm,
        nonce
      }
    );
    expect(verified).toBe(true);
  });
  it.each(cartesian([systems, schemes, algorithms]))(
    'failure - forged message - over %s/%s/%s', async ( system, scheme, algorithm) => {
    const ctx = initBackend(system);
    const { privateKey, publicKey } = await generateKey(ctx);
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const signature = await privateKey.signMessage(message, { scheme, algorithm });
    const forgedMessage = Uint8Array.from(Buffer.from('don\' t destroy earth'));
    await expect(
      publicKey.verifySignature(
        forgedMessage,
        signature, {
          scheme,
          algorithm
        }
      )
    ).rejects.toThrow(
      'Invalid signature'
    );
  });
  it.each(cartesian([systems, schemes, algorithms]))(
    'failure - forged signature - over %s/%s/%s', async (system, scheme, algorithm) => {
    const ctx = initBackend(system);
    const { privateKey, publicKey } = await generateKey(ctx);
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const signature = await privateKey.signMessage(message, { scheme, algorithm });
    signature.c! = (await ctx.randomPoint()).toBytes();
    await expect(
      publicKey.verifySignature(
        message, signature, {
          scheme,
          algorithm
        }
      )
    ).rejects.toThrow(
      'Invalid signature'
    );
  });
  it.each(cartesian([systems, schemes, algorithms]))(
    'failure - forged nonce - over %s/%s/%s', async (system, scheme, algorithm) => {
    const ctx = initBackend(system);
    const { privateKey, publicKey } = await generateKey(ctx);
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const nonce = await randomNonce();
    const signature = await privateKey.signMessage(message, { scheme, algorithm, nonce });
    await expect(
      publicKey.verifySignature(
        message, signature, {
          scheme,
          algorithm
        }
      )
    ).rejects.toThrow(
      'Invalid signature'
    );
  });
  it.each(cartesian([systems, schemes, algorithms]))(
    'failure - missing nonce - over %s/%s/%s', async (system, scheme, algorithm) => {
    const ctx = initBackend(system);
    const { privateKey, publicKey } = await generateKey(ctx);
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const nonce = await randomNonce();
    const signature = await privateKey.signMessage(message, { scheme, algorithm, nonce });
    const forgedNonce = await randomNonce();
    await expect(
      publicKey.verifySignature(
        message, signature, {
          scheme,
          algorithm,
          nonce: forgedNonce,
        }
      )
    ).rejects.toThrow(
      'Invalid signature'
    );
  });
  it.each(cartesian([systems, schemes, algorithms]))(
    'failure - wrong algorithm - over %s/%s/%s', async (system, scheme, algorithm) => {
    const ctx = initBackend(system);
    const { privateKey, publicKey } = await generateKey(ctx);
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const signature = await privateKey.signMessage(message, { scheme, algorithm });
    await expect(
      publicKey.verifySignature(
        message, signature, {
          scheme,
          algorithm: (algorithm == Algorithms.SHA256 || algorithm == undefined) ?
            Algorithms.SHA512 :
            Algorithms.SHA256
        })
    ).rejects.toThrow(
      'Invalid signature'
    );
  });
});
