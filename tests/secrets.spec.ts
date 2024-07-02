import {
  generateSecret,
  extractPublic,
  isEqualSecret,
  isEqualPublic,
  isKeypair,
} from '../src/secrets';

import { initBackend } from '../src/backend';
import { resolveTestConfig } from './environ';

const { systems } = resolveTestConfig();


describe('Raw bytes infrastructure for asymmetric secrets', () => {
  it.each(systems)('secret generation - over %s', async (system) => {
    const ctx = initBackend(system);
    const { secret, publicBytes } = await generateSecret(ctx);
    expect(await isKeypair(ctx, secret, publicBytes)).toBe(true);

    const g = ctx.generator;
    const x = ctx.leBuff2Scalar(secret);
    const y = await ctx.unpackValid(publicBytes);
    expect(await y.equals(await ctx.exp(g, x))).toBe(true);
  });
  it.each(systems)('public extraction - over %s', async (system) => {
    const ctx = initBackend(system);
    const { secret, publicBytes: targetPublic } = await generateSecret(ctx);

    const publicBytes = await extractPublic(ctx, secret);
    expect(await isKeypair(ctx, secret, publicBytes)).toBe(true);
    expect(await isEqualPublic(ctx, publicBytes, targetPublic)).toBe(true);

    const g = ctx.generator;
    const x = ctx.leBuff2Scalar(secret);
    const y = await ctx.unpackValid(publicBytes);
    expect(await y.equals(await ctx.exp(g, x))).toBe(true);
  });
  it.each(systems)('key equality - over %s', async (system) => {
    const ctx = initBackend(system);
    const { secret, publicBytes } = await generateSecret(ctx);
    const sameSecret = Uint8Array.from(secret);
    const samePublic = Uint8Array.from(publicBytes);

    expect(await isEqualSecret(ctx, sameSecret, secret)).toBe(true);
    expect(await isEqualPublic(ctx, samePublic, publicBytes)).toBe(true);
    expect(await isKeypair(ctx, secret, samePublic)).toBe(true);
    expect(await isKeypair(ctx, sameSecret, publicBytes)).toBe(true);
  });
  it.each(systems)('key disparity - over %s', async (system) => {
    const ctx = initBackend(system);
    const { secret, publicBytes } = await generateSecret(ctx);
    const { secret: otherSecret, publicBytes: otherPublic } = await generateSecret(ctx);

    expect(await isEqualSecret(ctx, otherSecret, secret)).toBe(false);
    expect(await isEqualPublic(ctx, otherPublic, publicBytes)).toBe(false);
    expect(await isKeypair(ctx, secret, otherPublic)).toBe(false);
    expect(await isKeypair(ctx, otherSecret, publicBytes)).toBe(false);
  });
})

