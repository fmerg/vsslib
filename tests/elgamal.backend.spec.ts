import { Point } from '../src/elgamal/abstract';
import { Systems } from '../src/enums';

const backend = require('../src/elgamal/backend');

const __labels = Object.values(Systems);
const __zero   = BigInt(0)
const __one    = BigInt(1)


describe('group initialization', () => {
  it.each(__labels)('over %s', async (label) => {
    const group = backend.initGroup(label);
    expect(group.label).toEqual(label);
  });
})


describe('group initialization failure', () => {
  test('unsupported system', () => {
    const unsupported = 'unsupported';
    expect(() => backend.initGroup(unsupported)).toThrow(
      `Unsupported system: ${unsupported}`
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
    await group.assertValid(group.generator);

    const neutral = await group.generatePoint(__zero);
    expect(await neutral.isEqual(group.neutral)).toBe(true);
  });
});


describe('group generator', () => {
  it.each(__labels)('over %s', async (label) => {
    const group = backend.initGroup(label);
    await group.assertValid(group.generator);

    const generator = await group.generatePoint(__one);
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

    const minusOne = group.order - __one;             // TODO: scalar -1
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

    let expected = await group.operate(__zero, group.generator)
    expect(await group.neutral.isEqual(expected)).toBe(true);
    expected = await group.generatePoint(__zero)
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

    s = __zero;
    current = group.neutral;                                  // 0
    expected = await group.operate(s, p);                     // 0 * p
    expect(await current.isEqual(expected)).toBe(true);

    s += __one;
    current = p;                                              // p
    expected = await group.operate(s, p);                     // 1 * p
    expect(await current.isEqual(expected)).toBe(true);

    s += __one;
    current = await group.combine(p, current);                // p + p
    expected = await group.operate(s, p);                     // 2 * p
    expect(await current.isEqual(expected)).toBe(true);

    s += __one;
    current = await group.combine(p, current);                // p + (p + p)
    expected = await group.operate(s, p);                     // 3 * p
    expect(await current.isEqual(expected)).toBe(true);
  });
});


describe('hexify and unhexify point', () => {
  it.each(__labels)('over %s', async (label) => {
    const group = backend.initGroup(label);
    const p = await group.randomPoint();
    const packed = p.toHex();
    const unpacked = group.unhexify(packed);
    expect(await unpacked.isEqual(p)).toBe(true);
  })
});
