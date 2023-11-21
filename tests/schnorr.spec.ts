import { schnorr, backend } from '../src';
import { Systems, Algorithms } from '../src/enums';
import { cartesian } from './helpers';

const __labels      = Object.values(Systems);
const __algorithms  = [Algorithms.SHA256, Algorithms.SHA512, undefined];


describe('Signature verification - success without nonce', () => {
  it.each(cartesian([__labels, __algorithms]))('over %s/%s', async (label, algorithm) => {
    const ctx = backend.initGroup(label);
    const { secret, pub } = await ctx.generateKeypair();
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const signature = await schnorr(ctx, algorithm).signBytes(secret, message);
    const verified = await schnorr(ctx).verifyBytes(pub, message, signature);
    expect(verified).toBe(true);
  });
});


describe('Signature verification - success with nonce', () => {
  it.each(cartesian([__labels, __algorithms]))('over %s/%s', async (label, algorithm) => {
    const ctx = backend.initGroup(label);
    const { secret, pub } = await ctx.generateKeypair();
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const nonce = await ctx.randomBytes();
    const signature = await schnorr(ctx, algorithm).signBytes(secret, message, nonce);
    const verified = await schnorr(ctx).verifyBytes(pub, message, signature, nonce);
    expect(verified).toBe(true);
  });
});


describe('Signature verification - failure if forged message', () => {
  it.each(cartesian([__labels, __algorithms]))('over %s/%s', async (label, algorithm) => {
    const ctx = backend.initGroup(label);
    const { secret, pub } = await ctx.generateKeypair();
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const signature = await schnorr(ctx, algorithm).signBytes(secret, message);
    const forgedMessage = Uint8Array.from(Buffer.from('don\' t destroy earth'));
    const verified = await schnorr(ctx).verifyBytes(pub, forgedMessage, signature);
    expect(verified).toBe(false);
  });
});


describe('Signature verification - failure if forged key', () => {
  it.each(cartesian([__labels, __algorithms]))('over %s/%s', async (label, algorithm) => {
    const ctx = backend.initGroup(label);
    const { secret, pub } = await ctx.generateKeypair();
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const forgedSecret = await ctx.randomScalar();
    const signature = await schnorr(ctx, algorithm).signBytes(forgedSecret, message);
    const verified = await schnorr(ctx).verifyBytes(pub, message, signature);
    expect(verified).toBe(false);
  });
});


describe('Signature verification - failure if forged signature', () => {
  it.each(cartesian([__labels, __algorithms]))('over %s/%s', async (label, algorithm) => {
    const ctx = backend.initGroup(label);
    const { secret, pub } = await ctx.generateKeypair();
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const signature = await schnorr(ctx, algorithm).signBytes(secret, message);
    signature.commitments[0] = await ctx.randomPoint();
    const verified = await schnorr(ctx).verifyBytes(pub, message, signature);
    expect(verified).toBe(false);
  });
});


describe('Signature verification - failure if forged nonce', () => {
  it.each(cartesian([__labels, __algorithms]))('over %s/%s', async (label, algorithm) => {
    const ctx = backend.initGroup(label);
    const { secret, pub } = await ctx.generateKeypair();
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const nonce = await ctx.randomBytes();
    const signature = await schnorr(ctx, algorithm).signBytes(secret, message, nonce);
    const forgedNonce = await ctx.randomBytes();
    const verified = await schnorr(ctx).verifyBytes(pub, message, signature, forgedNonce);
    expect(verified).toBe(false);
  });
});


describe('Signature verification - failure if missing nonce', () => {
  it.each(cartesian([__labels, __algorithms]))('over %s/%s', async (label, algorithm) => {
    const ctx = backend.initGroup(label);
    const { secret, pub } = await ctx.generateKeypair();
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const nonce = await ctx.randomBytes();
    const signature = await schnorr(ctx, algorithm).signBytes(secret, message, nonce);
    const verified = await schnorr(ctx).verifyBytes(pub, message, signature);
    expect(verified).toBe(false);
  });
});
