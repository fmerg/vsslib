import { Algorithms } from '../../src/enums';
import { Algorithm } from '../../src/types';
import { initBackend, generateKey } from '../../src';
import { PrivateKey, PublicKey } from '../../src/keys';
import { cartesian } from '../utils';
import { resolveTestConfig } from '../environ';

const { systems } = resolveTestConfig();


describe('Public key extraction', () => {
  it.each(systems)('over %s', async (system) => {
    const ctx = initBackend(system);
    const { privateKey, publicKey } = await generateKey(ctx);
    const pubPoint = await publicKey.asPoint();
    const targetPoint = await ctx.exp(ctx.generator, privateKey.asScalar());
    const targetPublic = new PublicKey(ctx, targetPoint.toBytes());
    expect(await pubPoint.equals(targetPoint)).toBe(true);
    expect(await publicKey.equals(targetPublic)).toBe(true);
  });
});
