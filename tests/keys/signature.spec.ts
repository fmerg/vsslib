import { Algorithms, SignatureSchemes } from 'vsslib/enums';
import { Algorithm } from 'vsslib/types';
import { initBackend } from 'vsslib/backend';
import { generateKey } from 'vsslib/keys';
import { randomPublic } from 'vsslib/secrets';
import { randomNonce } from 'vsslib/crypto';
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
    const isValid = await publicKey.verifySignature(
      message, signature, {
        scheme,
        algorithm
      }
    );
    expect(isValid).toBe(true);
  });
  it.each(cartesian([systems, schemes, algorithms]))(
    'success - with nonce - over %s/%s/%s', async (system, scheme, algorithm) => {
    const ctx = initBackend(system);
    const { privateKey, publicKey } = await generateKey(ctx);
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const nonce = await randomNonce();
    const signature = await privateKey.signMessage(message, { scheme, algorithm, nonce });
    const isValid = await publicKey.verifySignature(
      message, signature, {
        scheme,
        algorithm,
        nonce
      }
    );
    expect(isValid).toBe(true);
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
    signature.c! = await randomPublic(ctx);
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
