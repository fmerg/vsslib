import { Point } from '../src/backend/abstract';
import { Systems } from '../src/enums';

const backend = require('../src/backend');

const __labels = Object.values(Systems);
const __0n     = BigInt(0)
const __1n     = BigInt(1)


describe('group initialization', () => {
  it.each(__labels)('over %s', async (label) => {
    const group = backend.initGroup(label);
    expect(group.label).toEqual(label);
  });
})


describe('group initialization failure', () => {
  test('unsupported crypto', () => {
    const unsupported = 'unsupported';
    expect(() => backend.initGroup(unsupported)).toThrow(
      `Unsupported crypto: ${unsupported}`
    );
  });
})


describe('group equality', () => {
  it.each(__labels)('over %s', async (label) => {
    const group = backend.initGroup(label);
    expect(await group.isEqual(backend.initGroup(label))).toBe(true);
    expect(await group.isEqual(
      backend.initGroup(
        label == Systems.ED25519 ?
          Systems.ED448 :
          Systems.ED25519
      )
    )).toBe(false);
  });
});


describe('neutral element', () => {
  it.each(__labels)('over %s', async (label) => {
    const group = backend.initGroup(label);
    await group.assertValid(group.neutral);

    const neutral = await group.generatePoint(__0n);
    expect(await neutral.isEqual(group.neutral)).toBe(true);
  });
});


describe('group generator', () => {
  it.each(__labels)('over %s', async (label) => {
    const group = backend.initGroup(label);
    await group.assertValid(group.generator);

    const generator = await group.generatePoint(__1n);
    expect(await generator.isEqual(group.generator)).toBe(true);
  });
});


describe('group law with neutral element', () => {
  it.each(__labels)('over %s', async (label) => {
    const group = backend.initGroup(label);

    const p = await group.randomPoint();
    const q = await group.combine(p, group.neutral);
    expect(await q.isEqual(p)).toBe(true);

    const u = await group.combine(group.neutral, p);
    expect(await u.isEqual(p)).toBe(true);
  });
});


describe('group law with random pair', () => {
  it.each(__labels)('over %s', async (label) => {
    const group = backend.initGroup(label);

    const r = await group.randomScalar();
    const s = await group.randomScalar();

    const p = await group.generatePoint(r);
    const q = await group.generatePoint(s);
    const u = await group.combine(p, q);

    const t = (r + s) % group.order;            // TODO: scalar combination
    const v = await group.generatePoint(t);

    expect(await v.isEqual(u)).toBe(true);
  });
});


describe('inverse of neutral', () => {
  it.each(__labels)('over %s', async (label) => {
    const group = backend.initGroup(label);

    const neutInv = await group.invert(group.neutral);
    expect(await neutInv.isEqual(group.neutral)).toBe(true);

    const neutral = await group.combine(group.neutral, neutInv);
    expect(await neutral.isEqual(group.neutral)).toBe(true);
  });
});


describe('inverse of generator', () => {
  it.each(__labels)('over %s', async (label) => {
    const group = backend.initGroup(label);

    const minusOne = group.order - __1n;             // TODO: scalar -1
    const expected = await group.generatePoint(minusOne);
    const genInv = await group.invert(group.generator);
    expect(await genInv.isEqual(expected)).toBe(true);

    const neutral = await group.combine(group.generator, genInv);
    expect(await neutral.isEqual(group.neutral)).toBe(true);
  });
});


describe('inverse of random point', () => {
  it.each(__labels)('over %s', async (label) => {
    const group = backend.initGroup(label);

    const r = await group.randomScalar();
    const p = await group.generatePoint(r);
    const pInv = await group.invert(p);

    const minusR = group.order - BigInt(r);             // TODO: scalar -r
    const expected = await group.generatePoint(minusR);
    expect(await pInv.isEqual(expected)).toBe(true);

    const neutral = await group.combine(p, pInv);
    expect(await neutral.isEqual(group.neutral)).toBe(true);
  });
});


describe('scalar operation on generator', () => {
  it.each(__labels)('over %s', async (label) => {
    const group = backend.initGroup(label);

    let expected = await group.operate(__0n, group.generator)
    expect(await group.neutral.isEqual(expected)).toBe(true);
    expected = await group.generatePoint(__0n)
    expect(await group.neutral.isEqual(expected)).toBe(true);

    const s = await group.randomScalar();
    const p = await group.generatePoint(s);
    const q = await group.operate(s, group.generator);
    expect(await q.isEqual(p)).toBe(true);
  })
});


describe('scalar operation on random point', () => {
  it.each(__labels)('over %s', async (label) => {
    const group = backend.initGroup(label);

    let s: bigint;
    let current: Point;
    let expected: Point

    const p = await group.randomPoint();                      // p

    s = __0n;
    current = group.neutral;                                  // 0
    expected = await group.operate(s, p);                     // 0 * p
    expect(await current.isEqual(expected)).toBe(true);

    s += __1n;
    current = p;                                              // p
    expected = await group.operate(s, p);                     // 1 * p
    expect(await current.isEqual(expected)).toBe(true);

    s += __1n;
    current = await group.combine(p, current);                // p + p
    expected = await group.operate(s, p);                     // 2 * p
    expect(await current.isEqual(expected)).toBe(true);

    s += __1n;
    current = await group.combine(p, current);                // p + (p + p)
    expected = await group.operate(s, p);                     // 3 * p
    expect(await current.isEqual(expected)).toBe(true);
  });
});


describe('point to bytes and back', () => {
  it.each(__labels)('over %s', async (label) => {
    const group = backend.initGroup(label);
    const p = await group.randomPoint();
    const pBytes = p.toBytes();
    const pBack = group.unpack(pBytes);
    expect(await pBack.isEqual(p)).toBe(true);
  })
});


describe('point to hex and back', () => {
  it.each(__labels)('over %s', async (label) => {
    const group = backend.initGroup(label);
    const p = await group.randomPoint();
    const pHex = p.toHex();
    const pBack = group.unhexify(pHex);
    expect(await pBack.isEqual(p)).toBe(true);
  })
});
