import { describe } from 'node:test';
import assert from 'node:assert/strict';
import { each } from '../utils';
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
  multiplyPublics,
} from 'vsslib/operations/secrets';
import { initBackend, InvalidInput } from 'vsslib';
import { intToLeBytes } from 'vsslib/arith';

import { resolveTestConfig } from '../environ';

const { systems } = resolveTestConfig();


describe('Raw bytes infrastructure for asymmetric secrets', () => {
  each(systems)('secret generation - over %s', async (system) => {
    const ctx = initBackend(system);
    const { secret, publicBytes } = await randomSecret(ctx);
    assert.equal(await isKeypair(ctx, secret, publicBytes), true);

    const g = ctx.generator;
    const x = await parseScalar(ctx, secret);
    const y = await parsePoint(ctx, publicBytes);
    assert.equal(await y.equals(await ctx.exp(g, x)), true);
  });
  each(systems)('public extraction - over %s', async (system) => {
    const ctx = initBackend(system);
    const { secret, publicBytes: targetPublic } = await randomSecret(ctx);

    const publicBytes = await extractPublic(ctx, secret);
    assert.equal(await isKeypair(ctx, secret, publicBytes), true);
    assert.equal(await isEqualPublic(ctx, publicBytes, targetPublic), true);

    const g = ctx.generator;
    const x = await parseScalar(ctx, secret);
    const y = await parsePoint(ctx, publicBytes);
    assert.equal(await y.equals(await ctx.exp(g, x)), true);
  });
  each(systems)('key equality - over %s', async (system) => {
    const ctx = initBackend(system);
    const { secret, publicBytes } = await randomSecret(ctx);
    const sameSecret = Uint8Array.from(secret);
    const samePublic = Uint8Array.from(publicBytes);

    assert.equal(await isEqualSecret(ctx, sameSecret, secret), true);
    assert.equal(await isEqualPublic(ctx, samePublic, publicBytes), true);
    assert.equal(await isKeypair(ctx, secret, samePublic), true);
    assert.equal(await isKeypair(ctx, sameSecret, publicBytes), true);
  });
  each(systems)('key disparity - over %s', async (system) => {
    const ctx = initBackend(system);
    const { secret, publicBytes } = await randomSecret(ctx);
    const { secret: otherSecret, publicBytes: otherPublic } = await randomSecret(ctx);

    assert.equal(await isEqualSecret(ctx, otherSecret, secret), false);
    assert.equal(await isEqualPublic(ctx, otherPublic, publicBytes), false);
    assert.equal(await isKeypair(ctx, secret, otherPublic), false);
    assert.equal(await isKeypair(ctx, otherSecret, publicBytes), false);
  });
  each(systems)('secrets differing in a single byte - over %s', async (system) => {
    const ctx = initBackend(system);
    const len = ctx.scalarBytes;
    const high = 1n << BigInt(8 * (len - 1));
    const pairs = [
      [high, high + 1n],  // differ in the first byte
      [1n, high + 1n],    // differ in the last byte
    ];
    for (const [a, b] of pairs) {
      const lhs = ctx.scalarToBytes(a);
      const rhs = ctx.scalarToBytes(b);
      assert.equal(await isEqualSecret(ctx, lhs, rhs), false);
      assert.equal(await isEqualSecret(ctx, lhs, Uint8Array.from(lhs)), true);
    }
  });
  each(systems)('secret-to-scalar roundtrip - over %s', async (system) => {
    const ctx = initBackend(system);
    const { secret } = await randomSecret(ctx);
    const scalar = await parseScalar(ctx, secret);
    assert.equal(await isEqualSecret(ctx, ctx.scalarToBytes(scalar), secret), true);
  });
  each(systems)('public-to-point roundtrip - over %s', async (system) => {
    const ctx = initBackend(system);
    const publicBytes = await randomPublic(ctx);
    const point = await parsePoint(ctx, publicBytes);
    assert.equal(await isEqualPublic(ctx, point.toBytes(), publicBytes), true);
  });
  each(systems)('summation of secrets - over %s', async (system) => {
    const ctx = initBackend(system);
    const secrets: Uint8Array[] = [];
    const publics: Uint8Array[] = [];
    const nrTotal = 10;
    for (let i = 0; i < nrTotal; i++) {
      const { secret, publicBytes } = await randomSecret(ctx);
      secrets.push(secret);
      publics.push(publicBytes);
    }

    // Examine zero secrets edge case
    const zeroSum = await addSecrets(ctx, []);
    const unitPublic = await multiplyPublics(ctx, []);
    assert.deepEqual(zeroSum, ctx.scalarToBytes(0n));
    assert.equal(await isEqualPublic(ctx, unitPublic, ctx.neutral.toBytes()), true);

    // Examine single secret edge case
    const cloneSecret = await addSecrets(ctx, secrets.slice(0, 1));
    const clonePublic = await multiplyPublics(ctx, publics.slice(0, 1));
    assert.equal(await isEqualSecret(ctx, cloneSecret, secrets[0]), true);
    assert.equal(await isEqualPublic(ctx, clonePublic, publics[0]), true);

    // Check commutation between addition of secrets and combination of publics
    for (let nr = 1; nr < nrTotal; nr++) {
      const secretSum = await addSecrets(ctx, secrets.slice(0, nr));
      const targetPublic = await extractPublic(ctx, secretSum);
      const overallPublic = await multiplyPublics(ctx, publics.slice(0, nr))
      assert.equal(await isEqualPublic(ctx, overallPublic, targetPublic), true);
    }
  });
  each(systems)('non-canonical secrets are rejected - over %s', async (system) => {
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
      await assert.rejects(extractPublic(ctx, bytes), InvalidInput);
      await assert.rejects(isKeypair(ctx, bytes, publicBytes), InvalidInput);
      await assert.rejects(isEqualSecret(ctx, bytes, secret), InvalidInput);
      await assert.rejects(addSecrets(ctx, [secret, bytes]), InvalidInput);
    }
  });
})
