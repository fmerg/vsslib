import { Systems } from '../src/enums';
import { initGroup } from '../src/backend';
import { Point } from '../src/backend/abstract';
import { ErrorMessages } from '../src/errors';
import { resolveTestConfig } from './environ';

const __0n = BigInt(0)
const __1n = BigInt(1)

const { systems } = resolveTestConfig();


describe('group initialization', () => {
  it.each(systems)('over %s', async (system) => {
    const ctx = initGroup(system);
    expect(ctx.system).toEqual(system);
  });
})


describe('group initialization failure', () => {
  test('unsupported group', () => {
    const system = 'foo';
    expect(() => initGroup(system).toThrow(
      `${ErrorMessages.UNSUPPORTED_GROUP}: ${system}`
    ))
  })
})


describe('group equality', () => {
  it.each(systems)('over %s', async (system) => {
    const ctx = initGroup(system);
    expect(await ctx.equals(initGroup(system))).toBe(true);
    expect(await ctx.equals(
      initGroup(
        system == Systems.ED25519 ?
          Systems.ED448 :
          Systems.ED25519
      )
    )).toBe(false);
  });
});


describe('neutral element', () => {
  it.each(systems)('over %s', async (system) => {
    const ctx = initGroup(system);
    await ctx.validatePoint(ctx.neutral);

    const neutral = await ctx.operate(__0n, ctx.generator);
    expect(await neutral.equals(ctx.neutral)).toBe(true);
  });
});


describe('group generator', () => {
  it.each(systems)('over %s', async (system) => {
    const ctx = initGroup(system);
    await ctx.validatePoint(ctx.generator);

    const generator = await ctx.operate(__1n, ctx.generator);
    expect(await generator.equals(ctx.generator)).toBe(true);
  });
});


describe('group law with neutral element', () => {
  it.each(systems)('over %s', async (system) => {
    const ctx = initGroup(system);

    const p = await ctx.randomPoint();
    const q = await ctx.combine(p, ctx.neutral);
    expect(await q.equals(p)).toBe(true);

    const u = await ctx.combine(ctx.neutral, p);
    expect(await u.equals(p)).toBe(true);
  });
});


describe('group law with random pair', () => {
  it.each(systems)('over %s', async (system) => {
    const ctx = initGroup(system);

    const r = await ctx.randomScalar();
    const s = await ctx.randomScalar();

    const p = await ctx.operate(r, ctx.generator);
    const q = await ctx.operate(s, ctx.generator);
    const u = await ctx.combine(p, q);

    const t = (r + s) % ctx.order;            // TODO: scalar combination
    const v = await ctx.operate(t, ctx.generator);

    expect(await v.equals(u)).toBe(true);
  });
});


describe('inverse of neutral', () => {
  it.each(systems)('over %s', async (system) => {
    const ctx = initGroup(system);

    const neutInv = await ctx.invert(ctx.neutral);
    expect(await neutInv.equals(ctx.neutral)).toBe(true);

    const neutral = await ctx.combine(ctx.neutral, neutInv);
    expect(await neutral.equals(ctx.neutral)).toBe(true);
  });
});


describe('inverse of generator', () => {
  it.each(systems)('over %s', async (system) => {
    const ctx = initGroup(system);

    const minusOne = ctx.order - __1n;             // TODO: scalar -1
    const expected = await ctx.operate(minusOne, ctx.generator);
    const genInv = await ctx.invert(ctx.generator);
    expect(await genInv.equals(expected)).toBe(true);

    const neutral = await ctx.combine(ctx.generator, genInv);
    expect(await neutral.equals(ctx.neutral)).toBe(true);
  });
});


describe('inverse of random point', () => {
  it.each(systems)('over %s', async (system) => {
    const ctx = initGroup(system);

    const r = await ctx.randomScalar();
    const p = await ctx.operate(r, ctx.generator);
    const pInv = await ctx.invert(p);

    const minusR = ctx.order - BigInt(r);             // TODO: scalar -r
    const expected = await ctx.operate(minusR, ctx.generator);
    expect(await pInv.equals(expected)).toBe(true);

    const neutral = await ctx.combine(p, pInv);
    expect(await neutral.equals(ctx.neutral)).toBe(true);
  });
});


describe('scalar operation on generator', () => {
  it.each(systems)('over %s', async (system) => {
    const ctx = initGroup(system);

    let expected = await ctx.operate(__0n, ctx.generator)
    expect(await ctx.neutral.equals(expected)).toBe(true);
    expected = await ctx.operate(__0n, ctx.generator)
    expect(await ctx.neutral.equals(expected)).toBe(true);

    const s = await ctx.randomScalar();
    const p = await ctx.operate(s, ctx.generator);
    const q = await ctx.operate(s, ctx.generator);
    expect(await q.equals(p)).toBe(true);
  })
});


describe('scalar operation on random point', () => {
  it.each(systems)('over %s', async (system) => {
    const ctx = initGroup(system);

    let s: bigint;
    let current: Point;
    let expected: Point

    const p = await ctx.randomPoint();                      // p

    s = __0n;
    current = ctx.neutral;                                  // 0
    expected = await ctx.operate(s, p);                     // 0 * p
    expect(await current.equals(expected)).toBe(true);

    s += __1n;
    current = p;                                              // p
    expected = await ctx.operate(s, p);                     // 1 * p
    expect(await current.equals(expected)).toBe(true);

    s += __1n;
    current = await ctx.combine(p, current);                // p + p
    expected = await ctx.operate(s, p);                     // 2 * p
    expect(await current.equals(expected)).toBe(true);

    s += __1n;
    current = await ctx.combine(p, current);                // p + (p + p)
    expected = await ctx.operate(s, p);                     // 3 * p
    expect(await current.equals(expected)).toBe(true);
  });
});


describe('point to bytes and back', () => {
  it.each(systems)('over %s', async (system) => {
    const ctx = initGroup(system);
    const p = await ctx.randomPoint();
    const pBytes = p.toBytes();
    const pBack = ctx.unpack(pBytes);
    expect(await pBack.equals(p)).toBe(true);
  })
});


describe('point to hex and back', () => {
  it.each(systems)('over %s', async (system) => {
    const ctx = initGroup(system);
    const p = await ctx.randomPoint();
    const pHex = p.toHex();
    const pBack = ctx.unhexify(pHex);
    expect(await pBack.equals(p)).toBe(true);
  })
});


describe('scalar validation', () => {
  it.each(systems)('over %s', async (system) => {
    const ctx = initGroup(system);
    const s = await ctx.randomScalar();
    const isValid = await ctx.validateScalar(s);
    expect(isValid).toBe(true);
    const t = ctx.order;
    await expect(ctx.validateScalar(t)).rejects.toThrow(
      ErrorMessages.INVALID_SCALAR
    );
  })
});


describe('bytes validation', () => {
  it.each(systems)('over %s', async (system) => {
    const ctx = initGroup(system);
    const b = await ctx.randomBytes();
    const isValid = await ctx.validateBytes(b);
    expect(isValid).toBe(true);
    const c = Uint8Array.from([...b, 0]);
    await expect(ctx.validateBytes(c)).rejects.toThrow(
      ErrorMessages.INVALID_BYTELENGTH
    );
  })
});


describe('Keypair generation - no given secret', () => {
  it.each(systems)('over %s', async (system) => {
    const ctx = initGroup(system);
    const { secret, pub } = await ctx.generateKeypair();
    expect(await pub.equals(await ctx.operate(secret, ctx.generator))).toBe(true);
  })
});

describe('Keypair generation - given secret', () => {
  it.each(systems)('over %s', async (system) => {
    const ctx = initGroup(system);
    const scalar = await ctx.randomScalar();
    const { secret, pub } = await ctx.generateKeypair(scalar);
    expect(secret).toEqual(scalar);
    expect(await pub.equals(await ctx.operate(scalar, ctx.generator))).toBe(true);
  })
});
