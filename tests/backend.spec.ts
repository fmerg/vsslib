import { Point } from 'vsslib/backend';
import { Systems } from 'vsslib/enums';
import { initBackend } from 'vsslib/backend';
import { resolveTestConfig } from './environ';

const __0n = BigInt(0)
const __1n = BigInt(1)

const { systems } = resolveTestConfig();


describe('group initialization - success', () => {
  it.each(systems)('over %s', async (system) => {
    const ctx = initBackend(system);
    expect(ctx.system).toEqual(system);
  });
})

describe('group initialization - failure', () => {
  test('unsupported group', () => {
    const system = 'foo';
    expect(() => initBackend(system)).toThrow(
      `Unsupported group: ${system}`
    )
  })
})

describe('neutral element', () => {
  it.each(systems)('over %s', async (system) => {
    const ctx = initBackend(system);
    await ctx.validatePoint(ctx.neutral);
    const neutral = await ctx.exp(ctx.generator, __0n);
    expect(await neutral.equals(ctx.neutral)).toBe(true);
  });
});

describe('group generator', () => {
  it.each(systems)('over %s', async (system) => {
    const ctx = initBackend(system);
    await ctx.validatePoint(ctx.generator);
    const generator = await ctx.exp(ctx.generator, __1n);
    expect(await generator.equals(ctx.generator)).toBe(true);
  });
});

describe('group operation', () => {
  it.each(systems)('neutral element - over %s', async (system) => {
    const ctx = initBackend(system);
    const p = await ctx.randomPoint();
    const q = await ctx.operate(p, ctx.neutral);
    expect(await q.equals(p)).toBe(true);
    const u = await ctx.operate(ctx.neutral, p);
    expect(await u.equals(p)).toBe(true);
  });
  it.each(systems)('random pair - over %s', async (system) => {
    const ctx = initBackend(system);
    const r = await ctx.randomScalar();
    const s = await ctx.randomScalar();
    const p = await ctx.exp(ctx.generator, r);
    const q = await ctx.exp(ctx.generator, s);
    const u = await ctx.operate(p, q);
    const t = (r + s) % ctx.order;
    const v = await ctx.exp(ctx.generator, t);
    expect(await v.equals(u)).toBe(true);
  });
});

describe('inverse', () => {
  it.each(systems)('neutral - over %s', async (system) => {
    const ctx = initBackend(system);
    const neutInv = await ctx.invert(ctx.neutral);
    expect(await neutInv.equals(ctx.neutral)).toBe(true);
    const neutral = await ctx.operate(ctx.neutral, neutInv);
    expect(await neutral.equals(ctx.neutral)).toBe(true);
  });
  it.each(systems)('generator - over %s', async (system) => {
    const ctx = initBackend(system);
    const minusOne = ctx.order - __1n;             // TODO: scalar -1
    const expected = await ctx.exp(ctx.generator, minusOne);
    const genInv = await ctx.invert(ctx.generator);
    expect(await genInv.equals(expected)).toBe(true);
    const neutral = await ctx.operate(ctx.generator, genInv);
    expect(await neutral.equals(ctx.neutral)).toBe(true);
  });
  it.each(systems)('random point - over %s', async (system) => {
    const ctx = initBackend(system);
    const r = await ctx.randomScalar();
    const p = await ctx.exp(ctx.generator, r);
    const pInv = await ctx.invert(p);
    const minusR = ctx.order - BigInt(r);
    const expected = await ctx.exp(ctx.generator, minusR);
    expect(await pInv.equals(expected)).toBe(true);
    const neutral = await ctx.operate(p, pInv);
    expect(await neutral.equals(ctx.neutral)).toBe(true);
  });
});

describe('exponentiation', () => {
  it.each(systems)('generator - over %s', async (system) => {
    const ctx = initBackend(system);

    let expected = await ctx.exp(ctx.generator, __0n)
    expect(await ctx.neutral.equals(expected)).toBe(true);
    expected = await ctx.exp(ctx.generator, __0n);
    expect(await ctx.neutral.equals(expected)).toBe(true);

    const s = await ctx.randomScalar();
    const p = await ctx.exp(ctx.generator, s);
    const q = await ctx.exp(ctx.generator, s);
    expect(await q.equals(p)).toBe(true);
  })
  it.each(systems)('random point - over %s', async (system) => {
    const ctx = initBackend(system);
    let s: bigint;
    let current: any;
    let expected: any

    const p = await ctx.randomPoint();                    // p

    s = __0n;
    current = ctx.neutral;                                // 0
    expected = await ctx.exp(p, s);                       // 0 * p
    expect(await current.equals(expected)).toBe(true);

    s += __1n;
    current = p;                                          // p
    expected = await ctx.exp(p, s);                       // 1 * p
    expect(await current.equals(expected)).toBe(true);

    s += __1n;
    current = await ctx.operate(p, current);              // p + p
    expected = await ctx.exp(p, s);                       // 2 * p
    expect(await current.equals(expected)).toBe(true);

    s += __1n;
    current = await ctx.operate(p, current);              // p + (p + p)
    expected = await ctx.exp(p, s);                       // 3 * p
    expect(await current.equals(expected)).toBe(true);
  });
});

describe('point to bytes and back', () => {
  it.each(systems)('success over %s', async (system) => {
    const ctx = initBackend(system);
    const p = await ctx.randomPoint();
    const buff = p.toBytes();
    const pBack = ctx.buff2Point(buff)
    expect(await pBack.equals(p)).toBe(true);
  })
  it.each(systems)('failure over %s', async (system) => {
    const ctx = initBackend(system);
    const buff = Uint8Array.from(Buffer.from('foo'));
    expect(() => ctx.buff2Point(buff)).toThrow('bad encoding:');
  })
});

describe('scalar validation', () => {
  it.each(systems)('over %s', async (system) => {
    const ctx = initBackend(system);
    const s = await ctx.randomScalar();
    const isValid = await ctx.validateScalar(s);
    expect(isValid).toBe(true);
    const t = ctx.order;
    await expect(ctx.validateScalar(t)).rejects.toThrow(
      'Scalar not in range'
    );
  })
});
