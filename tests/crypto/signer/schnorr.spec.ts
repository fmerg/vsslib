import { Systems, Algorithms, SignatureSchemes } from '../../../src/schemes';
import { backend } from '../../../src';
import { cartesian } from '../../helpers';
import signer from '../../../src/crypto/signer';

import { resolveAlgorithms, resolveBackends } from '../../environ';

const __labels      = resolveBackends();
const __algorithms  = resolveAlgorithms();


describe('Signature verification - success without nonce', () => {
  it.each(cartesian([__labels, __algorithms]))('over %s/%s', async (label, algorithm) => {
    const ctx = backend.initGroup(label);
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
  it.each(cartesian([__labels, __algorithms]))('over %s/%s', async (label, algorithm) => {
    const ctx = backend.initGroup(label);
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
  it.each(cartesian([__labels, __algorithms]))('over %s/%s', async (label, algorithm) => {
    const ctx = backend.initGroup(label);
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
  it.each(cartesian([__labels, __algorithms]))('over %s/%s', async (label, algorithm) => {
    const ctx = backend.initGroup(label);
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
  it.each(cartesian([__labels, __algorithms]))('over %s/%s', async (label, algorithm) => {
    const ctx = backend.initGroup(label);
    const { secret, pub } = await ctx.generateKeypair();
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const signature = await signer(ctx, SignatureSchemes.SCHNORR, algorithm).signBytes(
      secret, message
    );
    signature.commitment = await ctx.randomPoint();
    const verified = await signer(ctx, SignatureSchemes.SCHNORR, algorithm).verifyBytes(
      pub, message, signature
    );
    expect(verified).toBe(false);
  });
});


describe('Signature verification - failure if forged nonce', () => {
  it.each(cartesian([__labels, __algorithms]))('over %s/%s', async (label, algorithm) => {
    const ctx = backend.initGroup(label);
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
  it.each(cartesian([__labels, __algorithms]))('over %s/%s', async (label, algorithm) => {
    const ctx = backend.initGroup(label);
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
