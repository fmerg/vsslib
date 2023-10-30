import { Systems } from '../src/enums';
const { backend, key, Key, Public } = require('../src')

const __labels = Object.values(Systems);


describe('construct key', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);

    const priv1 = await key.generate(label);
    const priv2 = new Key(ctx, priv1.secret, priv1.seed);
    expect(await priv1.isEqual(priv2)).toBe(true);

    const point1 = await priv1.point;
    const point2 = await priv2.point;
    expect(await point2.isEqual(point1)).toBe(true);

    const pub1 = await priv1.extractPublic();
    const pub2 = await priv2.extractPublic();
    expect(await pub2.isEqual(pub1)).toBe(true);
  });
});


describe('extract public', () => {
  it.each(__labels)('over %s', async (label) => {
    const priv = await key.generate(label);
    const pub = await priv.extractPublic();
    expect(await pub.ctx.isEqual(priv.ctx)).toBe(true);
    expect(await pub.point.isEqual(await priv.ctx.operate(priv.secret, priv.ctx.generator)));
  });
});


describe('serialize key', () => {
  it.each(__labels)('over %s', async (label) => {
    const priv = await key.generate(label);
    const serialized = priv.serialize();
    const privBack = key.deserialize(serialized);
    expect(await privBack.isEqual(priv)).toBe(true);
  });
});


describe('serialize public', () => {
  it.each(__labels)('over %s', async (label) => {
    const priv = await key.generate(label);
    const pub = await priv.extractPublic();
    const serialized = pub.serialize()
    const pubBack = key.deserialize(serialized);
    expect(await pubBack.isEqual(pub)).toBe(true);
  });
});


describe('diffie-hellman', () => {
  it.each(__labels)('over %s', async (label) => {
    const priv1 = await key.generate(label);
    const pub1 = await priv1.extractPublic();

    const priv2 = await key.generate(label);
    const pub2 = await priv2.extractPublic();

    const pt1 = await priv1.diffieHellman(pub2);
    const pt2 = await priv2.diffieHellman(pub1);

    expect(await pt1.isEqual(pt2)).toBe(true);
  });
});


describe('encryption and decryption of point', () => {
  it.each(__labels)('over %s', async (label) => {
    const priv = await key.generate(label);
    const pub = await priv.extractPublic();

    const msgPoint = await priv.ctx.randomPoint();

    const [ciphertext, r] = await pub.encryptPoint(msgPoint);
    const plaintext = await priv.decryptPoint(ciphertext);
    expect(await plaintext.isEqual(msgPoint)).toBe(true);
  });
});
