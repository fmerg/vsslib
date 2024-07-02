import { initBackend, generateSecret } from '../src';
import { randomNonce } from '../src/crypto';

import { cartesian } from './utils';
import { resolveTestConfig } from './environ';

import signer from '../src/signer';

const { systems, algorithms, signatureSchemes: schemes} = resolveTestConfig();

describe('Signing operation', () => {
  it.each(cartesian([systems, schemes, algorithms]))(
    'success - without nonce - over %s/%s/%s', async (system, scheme, algorithm) => {
    const ctx = initBackend(system);
    const { secret, publicBytes } = await generateSecret(ctx);
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const signature = await signer(ctx, scheme, algorithm).signBytes(
      secret, message
    );
    const verified = await signer(ctx, scheme, algorithm).verifyBytes(
      publicBytes, message, signature
    );
    expect(verified).toBe(true);
  });
  it.each(cartesian([systems, schemes, algorithms]))(
    'success - with nonce - over %s/%s/%s', async (system, scheme, algorithm) => {
    const ctx = initBackend(system);
    const { secret, publicBytes } = await generateSecret(ctx);
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const nonce = await randomNonce();
    const signature = await signer(ctx, scheme, algorithm).signBytes(
      secret, message, nonce
    );
    const verified = await signer(ctx, scheme, algorithm).verifyBytes(
      publicBytes, message, signature, nonce
    );
    expect(verified).toBe(true);
  });
  it.each(cartesian([systems, schemes, algorithms]))(
    'failure - forged message - over %s/%s/%s', async (system, scheme, algorithm) => {
    const ctx = initBackend(system);
    const { secret, publicBytes } = await generateSecret(ctx);
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const signature = await signer(ctx, scheme, algorithm).signBytes(
      secret, message
    );
    const forgedMessage = Uint8Array.from(Buffer.from('don\' t destroy earth'));
    const verified = await signer(ctx, scheme, algorithm).verifyBytes(
      publicBytes, forgedMessage, signature
    );
    expect(verified).toBe(false);
  });
  it.each(cartesian([systems, schemes, algorithms]))(
    'failure - forged key - over %s/%s/%s', async (system, scheme, algorithm) => {
    const ctx = initBackend(system);
    const { secret, publicBytes } = await generateSecret(ctx);
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const { secret: forgedSecret } = await generateSecret(ctx);
    const signature = await signer(ctx, scheme, algorithm).signBytes(
      forgedSecret, message
    );
    const verified = await signer(ctx, scheme, algorithm).verifyBytes(
      publicBytes, message, signature
    );
    expect(verified).toBe(false);
  });
  it.each(cartesian([systems, schemes, algorithms]))(
    'failure - forged signature - over %s/%s/%s', async (system, scheme, algorithm) => {
    const ctx = initBackend(system);
    const { secret, publicBytes } = await generateSecret(ctx);
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const signature = await signer(ctx, scheme, algorithm).signBytes(
      secret, message
    );
    signature.c = await ctx.randomPublic();
    const verified = await signer(ctx, scheme, algorithm).verifyBytes(
      publicBytes, message, signature
    );
    expect(verified).toBe(false);
  });
  it.each(cartesian([systems, schemes, algorithms]))(
    'failure - forged nonce - over %s/%s/%s', async (system, scheme, algorithm) => {
    const ctx = initBackend(system);
    const { secret, publicBytes } = await generateSecret(ctx);
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const nonce = await randomNonce();
    const signature = await signer(ctx, scheme, algorithm).signBytes(
      secret, message, nonce
    );
    const forgedNonce = await randomNonce();
    const verified = await signer(ctx, scheme, algorithm).verifyBytes(
      publicBytes, message, signature, forgedNonce
    );
    expect(verified).toBe(false);
  });
  it.each(cartesian([systems, schemes, algorithms]))(
    'failure - missing nonce - over %s/%s/%s', async (system, scheme, algorithm) => {
    const ctx = initBackend(system);
    const { secret, publicBytes } = await generateSecret(ctx);
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const nonce = await randomNonce();
    const signature = await signer(ctx, scheme, algorithm).signBytes(
      secret, message, nonce
    );
    const verified = await signer(ctx, scheme, algorithm).verifyBytes(
      publicBytes, message, signature
    );
    expect(verified).toBe(false);
  });
});
