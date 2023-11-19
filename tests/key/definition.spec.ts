import { Algorithms, Systems } from '../../src/enums';
import { Messages } from '../../src/key/enums';
import { Algorithm } from '../../src/types';
const { backend, key, PrivateKey, PublicKey } = require('../../src')
import { cartesian } from '../helpers';

const __labels = Object.values(Systems);
const __algorithms  = [...Object.values(Algorithms), undefined];


describe('Key generation', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const { privateKey, publicKey } = await key.generate(label);
    const private1 = await PrivateKey.fromScalar(ctx, privateKey.scalar);
    const private2 = await PrivateKey.fromBytes(ctx, privateKey.bytes);
    expect(await private1.isEqual(privateKey)).toBe(true);
    expect(await private2.isEqual(privateKey)).toBe(true);
    const public1 = await PublicKey.fromPoint(ctx, publicKey.point);
    expect(await public1.isEqual(publicKey)).toBe(true);
  });
});


describe('Key serialization and deserialization', () => {
  it.each(__labels)('over %s', async (label) => {
    const { privateKey, publicKey } = await key.generate(label);

    // Private counterpart
    const privSerialized = privateKey.serialize();
    expect(privSerialized).toEqual({
      value: Buffer.from(privateKey.bytes).toString('hex'),
      system: privateKey.ctx.label,
    });
    const privateBack = await PrivateKey.deserialize(privSerialized);
    expect(await privateBack.isEqual(privateKey)).toBe(true);

    // Public counterpart
    const pubSerialized = publicKey.serialize();
    expect(pubSerialized).toEqual({
      value: Buffer.from(publicKey.bytes).toString('hex'),
      system: publicKey.ctx.label,
    });
    const publicBack = await PublicKey.deserialize(pubSerialized);
    expect(await publicBack.isEqual(publicKey)).toBe(true);
  });
});


describe('Public key extraction', () => {
  it.each(__labels)('over %s', async (label) => {
    const { privateKey, publicKey } = await key.generate(label);
    const ctx = privateKey.ctx;
    expect(await publicKey.ctx.isEqual(privateKey.ctx)).toBe(true);
    expect(await publicKey.point.isEqual(await ctx.operate(privateKey.scalar, ctx.generator)));
  });
});


describe('Diffie-Hellman handshake', () => {
  it.each(__labels)('over %s', async (label) => {
    const { privateKey: private1, publicKey: public1 } = await key.generate(label);
    const { privateKey: private2, publicKey: public2 } = await key.generate(label);
    const point1 = await private1.diffieHellman(public2);
    const point2 = await private2.diffieHellman(public1);
    const expected = await private1.ctx.operate(private1.scalar, public2.point);
    expect(await point1.isEqual(expected)).toBe(true);
    expect(await point2.isEqual(point1)).toBe(true);
  });
});
