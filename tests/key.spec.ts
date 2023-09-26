const { Key, Public } = require('../src');
import { Systems } from '../src/enums';

const elgamal = require('../src/elgamal');

const __labels = Object.values(Systems);


describe('construct key', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = elgamal.initCrypto(label);

    const key1 = await Key.generate({ crypto: label });
    const key2 = new Key(ctx, key1.secret, key1.seed);
    expect(await key1.isEqual(key2)).toBe(true);

    const point1 = await key1.point;
    const point2 = await key2.point;
    expect(await point2.isEqual(point1)).toBe(true);

    const pub1 = await key1.extractPublic();
    const pub2 = await key2.extractPublic();
    expect(await pub2.isEqual(pub1)).toBe(true);
  });
});


describe('extract public', () => {
  it.each(__labels)('over %s', async (label) => {
    const key = await Key.generate({ crypto: label});
    const pub = await key.extractPublic();
    expect(await pub.ctx.isEqual(key.ctx)).toBe(true);
    expect(await pub.point.isEqual(await key.ctx.generatePoint(key.secret)));
  });
});


describe('serialize key', () => {
  it.each(__labels)('over %s', async (label) => {
    const key = await Key.generate({ crypto: label });
    const serialized = await key.serialize();
    const keyBack = await Key.deserialize(serialized, { crypto: label });
    expect(await keyBack.isEqual(key)).toBe(true);
  });
});


describe('serialize public', () => {
  it.each(__labels)('over %s', async (label) => {
    const key = await Key.generate({ crypto: label });
    const pub = await key.extractPublic();
    const serialized = await pub.serialize()
    const pubBack = await Public.deserialize(serialized, { crypto: label });
    expect(await pubBack.isEqual(pub)).toBe(true);
  });
});


describe('diffie-hellman', () => {
  it.each(__labels)('over %s', async (label) => {
    const key1 = await Key.generate({ crypto: label });
    const pub1 = await key1.extractPublic();

    const key2 = await Key.generate({ crypto: label });
    const pub2 = await key2.extractPublic();

    const pt1 = await key1.diffieHellman(pub2);
    const pt2 = await key2.diffieHellman(pub1);

    expect(await pt1.isEqual(pt2)).toBe(true);
  });
});


describe('encryption and decryption of point', () => {
  it.each(__labels)('over %s', async (label) => {
    const key = await Key.generate({ crypto: label });
    const pub = await key.extractPublic();

    const msgPoint = await key.ctx.randomPoint();

    const [ciphertext, r] = await pub.encryptPoint(msgPoint);
    const plaintext = await key.decryptPoint(ciphertext);
    expect(await plaintext.isEqual(msgPoint)).toBe(true);
  });
});
