import { Systems, Algorithms, SignatureSchemes } from '../src/enums';
import { initGroup } from '../src/backend';
import { randomBytes } from '../src/crypto';
import { cartesian } from './helpers';
import { resolveTestConfig } from './environ';
import signer from '../src/signer';

const { systems, algorithms, signatureSchemes: schemes} = resolveTestConfig();

describe('Signature verification - success without nonce', () => {
  it.each(cartesian([systems, schemes, algorithms]))('over %s/%s/%s', async (
    system, scheme, algorithm
  ) => {
    const ctx = initGroup(system);
    const { secret, pub } = await ctx.generateSecret();
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const signature = await signer(ctx, scheme, algorithm).signBytes(
      secret, message
    );
    const verified = await signer(ctx, scheme, algorithm).verifyBytes(
      pub.toBytes(), message, signature
    );
    expect(verified).toBe(true);
  });
});


describe('Signature verification - success with nonce', () => {
  it.each(cartesian([systems, schemes, algorithms]))('over %s/%s/%s', async (
    system, scheme, algorithm
  ) => {
    const ctx = initGroup(system);
    const { secret, pub } = await ctx.generateSecret();
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const nonce = await randomBytes(16);
    const signature = await signer(ctx, scheme, algorithm).signBytes(
      secret, message, nonce
    );
    const verified = await signer(ctx, scheme, algorithm).verifyBytes(
      pub.toBytes(), message, signature, nonce
    );
    expect(verified).toBe(true);
  });
});


describe('Signature verification - failure if forged message', () => {
  it.each(cartesian([systems, schemes, algorithms]))('over %s/%s/%s', async (
    system, scheme, algorithm
  ) => {
    const ctx = initGroup(system);
    const { secret, pub } = await ctx.generateSecret();
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const signature = await signer(ctx, scheme, algorithm).signBytes(
      secret, message
    );
    const forgedMessage = Uint8Array.from(Buffer.from('don\' t destroy earth'));
    const verified = await signer(ctx, scheme, algorithm).verifyBytes(
      pub.toBytes(), forgedMessage, signature
    );
    expect(verified).toBe(false);
  });
});


describe('Signature verification - failure if forged key', () => {
  it.each(cartesian([systems, schemes, algorithms]))('over %s/%s/%s', async (
    system, scheme, algorithm
  ) => {
    const ctx = initGroup(system);
    const { secret, pub } = await ctx.generateSecret();
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const forgedSecret = await ctx.randomScalar();
    const signature = await signer(ctx, scheme, algorithm).signBytes(
      forgedSecret, message
    );
    const verified = await signer(ctx, scheme, algorithm).verifyBytes(
      pub.toBytes(), message, signature
    );
    expect(verified).toBe(false);
  });
});


describe('Signature verification - failure if forged signature', () => {
  it.each(cartesian([systems, schemes, algorithms]))('over %s/%s/%s', async (
    system, scheme, algorithm
  ) => {
    const ctx = initGroup(system);
    const { secret, pub } = await ctx.generateSecret();
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const signature = await signer(ctx, scheme, algorithm).signBytes(
      secret, message
    );
    signature.c = (await ctx.randomPoint()).toBytes();
    const verified = await signer(ctx, scheme, algorithm).verifyBytes(
      pub.toBytes(), message, signature
    );
    expect(verified).toBe(false);
  });
});


describe('Signature verification - failure if forged nonce', () => {
  it.each(cartesian([systems, schemes, algorithms]))('over %s/%s/%s', async (
    system, scheme, algorithm
  ) => {
    const ctx = initGroup(system);
    const { secret, pub } = await ctx.generateSecret();
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const nonce = await randomBytes(16);
    const signature = await signer(ctx, scheme, algorithm).signBytes(
      secret, message, nonce
    );
    const forgedNonce = await randomBytes(16);
    const verified = await signer(ctx, scheme, algorithm).verifyBytes(
      pub.toBytes(), message, signature, forgedNonce
    );
    expect(verified).toBe(false);
  });
});


describe('Signature verification - failure if missing nonce', () => {
  it.each(cartesian([systems, schemes, algorithms]))('over %s/%s/%s', async (
    system, scheme, algorithm
  ) => {
    const ctx = initGroup(system);
    const { secret, pub } = await ctx.generateSecret();
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const nonce = await randomBytes(16);
    const signature = await signer(ctx, scheme, algorithm).signBytes(
      secret, message, nonce
    );
    const verified = await signer(ctx, scheme, algorithm).verifyBytes(
      pub.toBytes(), message, signature
    );
    expect(verified).toBe(false);
  });
});
