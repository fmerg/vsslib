import { initGroup } from '../../src/backend';
import { Algorithms } from '../../src/enums';
import { Algorithm } from '../../src/types';
import { generateKey } from '../../src';
import { PrivateKey, PublicKey } from '../../src/keys';
import { cartesian } from '../helpers';
import { resolveTestConfig } from '../environ';

const { systems } = resolveTestConfig();


describe('Public key extraction', () => {
  it.each(systems)('over %s', async (system) => {
    const { privateKey, publicKey, ctx } = await generateKey(system);
    const pubPoint = await publicKey.asPoint();
    const targetPoint = await ctx.exp(privateKey.asScalar(), ctx.generator);
    const targetPublic = new PublicKey(ctx, targetPoint.toBytes());
    expect(await pubPoint.equals(targetPoint)).toBe(true);
    expect(await publicKey.equals(targetPublic)).toBe(true);
  });
});
