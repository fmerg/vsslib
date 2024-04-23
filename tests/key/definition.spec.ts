import { Algorithms, Algorithm, Systems } from '../../src/schemes';
import { Messages } from '../../src/key/enums';
const { backend, key, PrivateKey, PublicKey } = require('../../src')
import { cartesian } from '../helpers';
import { resolveBackends } from '../environ';

const __labels = resolveBackends();


describe('Key generation', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const { privateKey, publicKey } = await key.generate(label);
    const priv1 = await PrivateKey.fromScalar(ctx, privateKey.scalar);
    const priv2 = await PrivateKey.fromBytes(ctx, privateKey.bytes);
    expect(await priv1.equals(privateKey)).toBe(true);
    expect(await priv2.equals(privateKey)).toBe(true);
    const pub1 = await PublicKey.fromPoint(ctx, publicKey.point);
    expect(await pub1.equals(publicKey)).toBe(true);
  });
});


describe('Key serialization and deserialization', () => {
  it.each(__labels)('over %s', async (label) => {
    const { privateKey, publicKey, ctx } = await key.generate(label);

    // Private counterpart
    const privSerialized = privateKey.serialize();
    expect(privSerialized).toEqual({
      value: Buffer.from(privateKey.bytes).toString('hex'),
      system: ctx.label,
    });
    const privateBack = await PrivateKey.deserialize(privSerialized);
    expect(await privateBack.equals(privateKey)).toBe(true);

    // Public counterpart
    const pubSerialized = publicKey.serialize();
    expect(pubSerialized).toEqual({
      value: Buffer.from(publicKey.bytes).toString('hex'),
      system: ctx.label,
    });
    const publicBack = await PublicKey.deserialize(pubSerialized);
    expect(await publicBack.equals(publicKey)).toBe(true);
  });
});


describe('Public key extraction', () => {
  it.each(__labels)('over %s', async (label) => {
    const { privateKey, publicKey, ctx } = await key.generate(label);
    expect(await ctx.equals(ctx)).toBe(true);
    expect(await publicKey.point.equals(await ctx.operate(privateKey.scalar, ctx.generator)));
  });
});


describe('Diffie-Hellman handshake', () => {
  it.each(__labels)('over %s', async (label) => {
    const { privateKey: priv1, publicKey: pub1, ctx } = await key.generate(label);
    const { privateKey: priv2, publicKey: pub2 } = await key.generate(label);
    const point1 = await priv1.diffieHellman(pub2);
    const point2 = await priv2.diffieHellman(pub1);
    const expected = await ctx.operate(priv1.scalar, pub2.point);
    expect(await point1.equals(expected)).toBe(true);
    expect(await point2.equals(point1)).toBe(true);
  });
});
