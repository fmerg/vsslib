import {
  parseScalar,
  parsePoint,
  randomPublic,
  randomSecret,
  extractPublic,
  isEqualSecret,
  isEqualPublic,
  isKeypair,
  addSecrets,
  addPublics,
} from 'vsslib/operations/secrets';
import { initBackend } from 'vsslib/backend';
import { intToLeBytes } from 'vsslib/arith';
import { InvalidInput } from 'vsslib/errors';

import { resolveTestConfig } from './environ';

const { systems } = resolveTestConfig();


describe('Raw bytes infrastructure for asymmetric secrets', () => {
  it.each(systems)('secret generation - over %s', async (system) => {
    const ctx = initBackend(system);
    const { secret, publicBytes } = await randomSecret(ctx);
    expect(await isKeypair(ctx, secret, publicBytes)).toBe(true);

    const g = ctx.generator;
    const x = await parseScalar(ctx, secret);
    const y = await parsePoint(ctx, publicBytes);
    expect(await y.equals(await ctx.exp(g, x))).toBe(true);
  });
  it.each(systems)('public extraction - over %s', async (system) => {
    const ctx = initBackend(system);
    const { secret, publicBytes: targetPublic } = await randomSecret(ctx);

    const publicBytes = await extractPublic(ctx, secret);
    expect(await isKeypair(ctx, secret, publicBytes)).toBe(true);
    expect(await isEqualPublic(ctx, publicBytes, targetPublic)).toBe(true);

    const g = ctx.generator;
    const x = await parseScalar(ctx, secret);
    const y = await parsePoint(ctx, publicBytes);
    expect(await y.equals(await ctx.exp(g, x))).toBe(true);
  });
  it.each(systems)('key equality - over %s', async (system) => {
    const ctx = initBackend(system);
    const { secret, publicBytes } = await randomSecret(ctx);
    const sameSecret = Uint8Array.from(secret);
    const samePublic = Uint8Array.from(publicBytes);

    expect(await isEqualSecret(ctx, sameSecret, secret)).toBe(true);
    expect(await isEqualPublic(ctx, samePublic, publicBytes)).toBe(true);
    expect(await isKeypair(ctx, secret, samePublic)).toBe(true);
    expect(await isKeypair(ctx, sameSecret, publicBytes)).toBe(true);
  });
  it.each(systems)('key disparity - over %s', async (system) => {
    const ctx = initBackend(system);
    const { secret, publicBytes } = await randomSecret(ctx);
    const { secret: otherSecret, publicBytes: otherPublic } = await randomSecret(ctx);

    expect(await isEqualSecret(ctx, otherSecret, secret)).toBe(false);
    expect(await isEqualPublic(ctx, otherPublic, publicBytes)).toBe(false);
    expect(await isKeypair(ctx, secret, otherPublic)).toBe(false);
    expect(await isKeypair(ctx, otherSecret, publicBytes)).toBe(false);
  });
  it.each(systems)('secret-to-scalar roundtrip - over %s', async (system) => {
    const ctx = initBackend(system);
    const { secret } = await randomSecret(ctx);
    const scalar = await parseScalar(ctx, secret);
    expect(await isEqualSecret(ctx, ctx.scalarToBytes(scalar), secret)).toBe(true);
  });
  it.each(systems)('public-to-point roundtrip - over %s', async (system) => {
    const ctx = initBackend(system);
    const publicBytes = await randomPublic(ctx);
    const point = await parsePoint(ctx, publicBytes);
    expect(await isEqualPublic(ctx, point.toBytes(), publicBytes)).toBe(true);
  });
  it.each(systems)('summation of secrets - over %s', async (system) => {
    const ctx = initBackend(system);
    const secrets = [];
    const publics = [];
    const nrTotal = 10;
    for (let i = 0; i < nrTotal; i++) {
      const { secret, publicBytes } = await randomSecret(ctx);
      secrets.push(secret);
      publics.push(publicBytes);
    }

    // Examine zero secrets edge case
    const zeroSum = await addSecrets(ctx, []);
    const unitPublic = await addPublics(ctx, []);
    expect(zeroSum).toEqual(ctx.scalarToBytes(0n));
    expect(await isEqualPublic(ctx, unitPublic, ctx.neutral.toBytes())).toBe(true);

    // Examine single secret edge case
    const cloneSecret = await addSecrets(ctx, secrets.slice(0, 1));
    const clonePublic = await addPublics(ctx, publics.slice(0, 1));
    expect(await isEqualSecret(ctx, cloneSecret, secrets[0])).toBe(true);
    expect(await isEqualPublic(ctx, clonePublic, publics[0])).toBe(true);

    // Check commutation between addition of secrets and combination of publics
    for (let nr = 1; nr < nrTotal; nr++) {
      const secretSum = await addSecrets(ctx, secrets.slice(0, nr));
      const targetPublic = await extractPublic(ctx, secretSum);
      const overallPublic = await addPublics(ctx, publics.slice(0, nr))
      expect(await isEqualPublic(ctx, overallPublic, targetPublic)).toBe(true);
    }
  });
  it.each(systems)('non-canonical secrets are rejected - over %s', async (system) => {
    // Lenient decoding would accept many encodings per secret, e.g. s + q or
    // trailing zero bytes, and the zero secret, whose public is the neutral element
    const ctx = initBackend(system);
    const { order: q, scalarBytes: len } = ctx;
    const { secret, publicBytes } = await randomSecret(ctx);
    const s = await parseScalar(ctx, secret);
    const sameLength = s + q < (1n << BigInt(8 * len)) ? [intToLeBytes(s + q, len)] : [];
    const encodings = [
      ...sameLength,
      intToLeBytes(s, len + 1),
      intToLeBytes(0n, len),
      intToLeBytes(q, len),
    ];
    for (const bytes of encodings) {
      await expect(extractPublic(ctx, bytes)).rejects.toThrow(InvalidInput);
      await expect(isKeypair(ctx, bytes, publicBytes)).rejects.toThrow(InvalidInput);
      await expect(isEqualSecret(ctx, bytes, secret)).rejects.toThrow(InvalidInput);
      await expect(addSecrets(ctx, [secret, bytes])).rejects.toThrow(InvalidInput);
    }
  });
})
