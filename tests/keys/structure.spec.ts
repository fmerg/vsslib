import { initBackend, generateKey } from '../../src';
import { PrivateKey, PublicKey } from '../../src/keys';
import { resolveTestConfig } from '../environ';

const { systems } = resolveTestConfig();


describe('Structure of asymmetric keys', () => {
  it.each(systems)('key generation - over %s', async (system) => {
    const ctx = initBackend(system);
    const { privateKey, publicKey } = await generateKey(ctx);

    const g = ctx.generator;
    const x = ctx.leBuff2Scalar(privateKey.asBytes());
    const y = await ctx.unpackValid(publicKey.asBytes());
    expect(await y.equals(await ctx.exp(g, x))).toBe(true);
  });
  it.each(systems)('public key extraction - over %s', async (system) => {
    const ctx = initBackend(system);
    const { privateKey, publicKey: targetPublic} = await generateKey(ctx);

    const publicKey = await privateKey.getPublicKey();
    expect(await publicKey.equals(targetPublic)).toBe(true);

    const g = ctx.generator;
    const x = ctx.leBuff2Scalar(privateKey.asBytes());
    const y = await ctx.unpackValid(publicKey.asBytes());
    expect(await y.equals(await ctx.exp(g, x))).toBe(true);
  });
  it.each(systems)('keypair equality - over %s', async (system) => {
    const ctx = initBackend(system);
    const { privateKey, publicKey } = await generateKey(ctx);

    const sameKey = new PrivateKey(ctx, privateKey.asBytes());
    const samePublic = new PublicKey(ctx, publicKey.asBytes());

    expect(await sameKey.equals(privateKey)).toBe(true);
    expect(await samePublic.equals(publicKey)).toBe(true);
  });
  it.each(systems)('keypair disparity - over %s', async (system) => {
    const ctx = initBackend(system);
    const { privateKey, publicKey } = await generateKey(ctx);
    const { privateKey: otherKey, publicKey: otherPublic } = await generateKey(ctx);

    expect(await otherKey.equals(privateKey)).toBe(false);
    expect(await otherPublic.equals(publicKey)).toBe(false);
  });
});
