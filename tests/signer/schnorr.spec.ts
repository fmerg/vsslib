import { Systems, Algorithms, SignatureSchemes } from '../../src/enums';
import { initGroup } from '../../src/backend';
import { cartesian } from '../helpers';
import { resolveTestConfig } from '../environ';
import signer from '../../src/signer';

const { systems, algorithms } = resolveTestConfig();


describe('Signature verification - success without nonce', () => {
  it.each(cartesian([systems, algorithms]))('over %s/%s', async (system, algorithm) => {
    const ctx = initGroup(system);
    const { secret, pub } = await ctx.generateKeypair();
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const signature = await signer(ctx, SignatureSchemes.SCHNORR, algorithm).signBytes(
      secret, message
    );
    const verified = await signer(ctx, SignatureSchemes.SCHNORR, algorithm).verifyBytes(
      pub, message, signature
    );
    expect(verified).toBe(true);
  });
});


describe('Signature verification - success with nonce', () => {
  it.each(cartesian([systems, algorithms]))('over %s/%s', async (system, algorithm) => {
    const ctx = initGroup(system);
    const { secret, pub } = await ctx.generateKeypair();
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const nonce = await ctx.randomBytes();
    const signature = await signer(ctx, SignatureSchemes.SCHNORR, algorithm).signBytes(
      secret, message, nonce
    );
    const verified = await signer(ctx, SignatureSchemes.SCHNORR, algorithm).verifyBytes(
      pub, message, signature, nonce
    );
    expect(verified).toBe(true);
  });
});


describe('Signature verification - failure if forged message', () => {
  it.each(cartesian([systems, algorithms]))('over %s/%s', async (system, algorithm) => {
    const ctx = initGroup(system);
    const { secret, pub } = await ctx.generateKeypair();
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const signature = await signer(ctx, SignatureSchemes.SCHNORR, algorithm).signBytes(
      secret, message
    );
    const forgedMessage = Uint8Array.from(Buffer.from('don\' t destroy earth'));
    const verified = await signer(ctx, SignatureSchemes.SCHNORR, algorithm).verifyBytes(
      pub, forgedMessage, signature
    );
    expect(verified).toBe(false);
  });
});


describe('Signature verification - failure if forged key', () => {
  it.each(cartesian([systems, algorithms]))('over %s/%s', async (system, algorithm) => {
    const ctx = initGroup(system);
    const { secret, pub } = await ctx.generateKeypair();
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const forgedSecret = await ctx.randomScalar();
    const signature = await signer(ctx, SignatureSchemes.SCHNORR, algorithm).signBytes(
      forgedSecret, message
    );
    const verified = await signer(ctx, SignatureSchemes.SCHNORR, algorithm).verifyBytes(
      pub, message, signature
    );
    expect(verified).toBe(false);
  });
});


describe('Signature verification - failure if forged signature', () => {
  it.each(cartesian([systems, algorithms]))('over %s/%s', async (system, algorithm) => {
    const ctx = initGroup(system);
    const { secret, pub } = await ctx.generateKeypair();
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const signature = await signer(ctx, SignatureSchemes.SCHNORR, algorithm).signBytes(
      secret, message
    );
    signature.c = (await ctx.randomPoint()).toBytes();
    const verified = await signer(ctx, SignatureSchemes.SCHNORR, algorithm).verifyBytes(
      pub, message, signature
    );
    expect(verified).toBe(false);
  });
});


describe('Signature verification - failure if forged nonce', () => {
  it.each(cartesian([systems, algorithms]))('over %s/%s', async (system, algorithm) => {
    const ctx = initGroup(system);
    const { secret, pub } = await ctx.generateKeypair();
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const nonce = await ctx.randomBytes();
    const signature = await signer(ctx, SignatureSchemes.SCHNORR, algorithm).signBytes(
      secret, message, nonce
    );
    const forgedNonce = await ctx.randomBytes();
    const verified = await signer(ctx, SignatureSchemes.SCHNORR, algorithm).verifyBytes(
      pub, message, signature, forgedNonce
    );
    expect(verified).toBe(false);
  });
});


describe('Signature verification - failure if missing nonce', () => {
  it.each(cartesian([systems, algorithms]))('over %s/%s', async (system, algorithm) => {
    const ctx = initGroup(system);
    const { secret, pub } = await ctx.generateKeypair();
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const nonce = await ctx.randomBytes();
    const signature = await signer(ctx, SignatureSchemes.SCHNORR, algorithm).signBytes(
      secret, message, nonce
    );
    const verified = await signer(ctx, SignatureSchemes.SCHNORR, algorithm).verifyBytes(
      pub, message, signature
    );
    expect(verified).toBe(false);
  });
});
