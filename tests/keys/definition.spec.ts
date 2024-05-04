import { Algorithms } from '../../src/enums';
import { Algorithm } from '../../src/types';
import { generateKey } from '../../src';
import { PrivateKey, PublicKey } from '../../src/keys';
import { cartesian } from '../helpers';
import { resolveTestConfig } from '../environ';

const { systems } = resolveTestConfig();


describe('Key generation', () => {
  it.each(systems)('over %s', async (system) => {
    const { privateKey, publicKey, ctx } = await generateKey(system);
    const priv1 = await PrivateKey.fromScalar(ctx, privateKey.secret);
    const priv2 = await PrivateKey.fromBytes(ctx, privateKey.bytes);
    expect(await priv1.equals(privateKey)).toBe(true);
    expect(await priv2.equals(privateKey)).toBe(true);
    const pub1 = await PublicKey.fromPoint(ctx, publicKey.toPoint());
    expect(await pub1.equals(publicKey)).toBe(true);
  });
});


describe('Public key extraction', () => {
  it.each(systems)('over %s', async (system) => {
    const { privateKey, publicKey, ctx } = await generateKey(system);
    expect(await ctx.equals(ctx)).toBe(true);
    expect(await publicKey.toPoint().equals(await ctx.operate(privateKey.secret, ctx.generator)));
  });
});


describe('Diffie-Hellman handshake', () => {
  it.each(systems)('over %s', async (system) => {
    const { privateKey: priv1, publicKey: pub1, ctx } = await generateKey(system);
    const { privateKey: priv2, publicKey: pub2 } = await generateKey(system);
    const point1 = await priv1.diffieHellman(pub2);
    const point2 = await priv2.diffieHellman(pub1);
    const expected = await ctx.operate(priv1.secret, pub2.toPoint());
    expect(await point1.equals(expected)).toBe(true);
    expect(await point2.equals(point1)).toBe(true);
  });
});
