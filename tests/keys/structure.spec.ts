import { initBackend, generateKey } from 'vsslib';
import { PrivateKey, PublicKey } from 'vsslib/keys';
import { unpackScalar, unpackPoint, isEqualSecret } from 'vsslib/secrets';
import { resolveTestConfig } from '../environ';

const { systems } = resolveTestConfig();

describe('Structure of asymmetric keys', () => {
  it.each(systems)('key generation - over %s', async (system) => {
    const ctx = initBackend(system);
    const { privateKey, publicKey } = await generateKey(ctx);

    const g = ctx.generator;
    const x = await unpackScalar(ctx, privateKey.asBytes());
    const y = await unpackPoint(ctx, publicKey.asBytes());
    expect(await y.equals(await ctx.exp(g, x))).toBe(true);
  });
  it.each(systems)('public key extraction - over %s', async (system) => {
    const ctx = initBackend(system);
    const { privateKey, publicKey: targetPublic} = await generateKey(ctx);

    const publicKey = await privateKey.getPublicKey();
    expect(await publicKey.equals(targetPublic)).toBe(true);

    const g = ctx.generator;
    const x = await unpackScalar(ctx, privateKey.asBytes());
    const y = await unpackPoint(ctx, publicKey.asBytes());
    expect(await y.equals(await ctx.exp(g, x))).toBe(true);
  });
  it.each(systems)('keypair equality - over %s', async (system) => {
    const ctx = initBackend(system);
    const { privateKey, publicKey } = await generateKey(ctx);

    const sameKey = new PrivateKey(ctx, privateKey.asBytes());
    const samePublic = new PublicKey(ctx, publicKey.asBytes());

    expect(await isEqualSecret(ctx, sameKey.secret, privateKey.secret)).toBe(true);
    expect(await samePublic.equals(publicKey)).toBe(true);
  });
  it.each(systems)('keypair disparity - over %s', async (system) => {
    const ctx = initBackend(system);
    const { privateKey, publicKey } = await generateKey(ctx);
    const { privateKey: otherKey, publicKey: otherPublic } = await generateKey(ctx);

    expect(await isEqualSecret(ctx, otherKey.secret, privateKey.secret)).toBe(false);
    expect(await otherPublic.equals(publicKey)).toBe(false);
  });
});
