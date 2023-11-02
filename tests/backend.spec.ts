import { backend } from '../src';
import { Systems } from '../src/enums';
import { Point } from '../src/backend/abstract';
import { Messages } from '../src/backend/enums';

const __labels = Object.values(Systems);
const __0n     = BigInt(0)
const __1n     = BigInt(1)


describe('group initialization', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    expect(ctx.label).toEqual(label);
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
    const ctx = backend.initGroup(label);
    expect(await ctx.isEqual(backend.initGroup(label))).toBe(true);
    expect(await ctx.isEqual(
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
    const ctx = backend.initGroup(label);
    await ctx.validatePoint(ctx.neutral);

    const neutral = await ctx.operate(__0n, ctx.generator);
    expect(await neutral.isEqual(ctx.neutral)).toBe(true);
  });
});


describe('group generator', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    await ctx.validatePoint(ctx.generator);

    const generator = await ctx.operate(__1n, ctx.generator);
    expect(await generator.isEqual(ctx.generator)).toBe(true);
  });
});


describe('group law with neutral element', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);

    const p = await ctx.randomPoint();
    const q = await ctx.combine(p, ctx.neutral);
    expect(await q.isEqual(p)).toBe(true);

    const u = await ctx.combine(ctx.neutral, p);
    expect(await u.isEqual(p)).toBe(true);
  });
});


describe('group law with random pair', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);

    const r = await ctx.randomScalar();
    const s = await ctx.randomScalar();

    const p = await ctx.operate(r, ctx.generator);
    const q = await ctx.operate(s, ctx.generator);
    const u = await ctx.combine(p, q);

    const t = (r + s) % ctx.order;            // TODO: scalar combination
    const v = await ctx.operate(t, ctx.generator);

    expect(await v.isEqual(u)).toBe(true);
  });
});


describe('inverse of neutral', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);

    const neutInv = await ctx.invert(ctx.neutral);
    expect(await neutInv.isEqual(ctx.neutral)).toBe(true);

    const neutral = await ctx.combine(ctx.neutral, neutInv);
    expect(await neutral.isEqual(ctx.neutral)).toBe(true);
  });
});


describe('inverse of generator', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);

    const minusOne = ctx.order - __1n;             // TODO: scalar -1
    const expected = await ctx.operate(minusOne, ctx.generator);
    const genInv = await ctx.invert(ctx.generator);
    expect(await genInv.isEqual(expected)).toBe(true);

    const neutral = await ctx.combine(ctx.generator, genInv);
    expect(await neutral.isEqual(ctx.neutral)).toBe(true);
  });
});


describe('inverse of random point', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);

    const r = await ctx.randomScalar();
    const p = await ctx.operate(r, ctx.generator);
    const pInv = await ctx.invert(p);

    const minusR = ctx.order - BigInt(r);             // TODO: scalar -r
    const expected = await ctx.operate(minusR, ctx.generator);
    expect(await pInv.isEqual(expected)).toBe(true);

    const neutral = await ctx.combine(p, pInv);
    expect(await neutral.isEqual(ctx.neutral)).toBe(true);
  });
});


describe('scalar operation on generator', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);

    let expected = await ctx.operate(__0n, ctx.generator)
    expect(await ctx.neutral.isEqual(expected)).toBe(true);
    expected = await ctx.operate(__0n, ctx.generator)
    expect(await ctx.neutral.isEqual(expected)).toBe(true);

    const s = await ctx.randomScalar();
    const p = await ctx.operate(s, ctx.generator);
    const q = await ctx.operate(s, ctx.generator);
    expect(await q.isEqual(p)).toBe(true);
  })
});


describe('scalar operation on random point', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);

    let s: bigint;
    let current: Point;
    let expected: Point

    const p = await ctx.randomPoint();                      // p

    s = __0n;
    current = ctx.neutral;                                  // 0
    expected = await ctx.operate(s, p);                     // 0 * p
    expect(await current.isEqual(expected)).toBe(true);

    s += __1n;
    current = p;                                              // p
    expected = await ctx.operate(s, p);                     // 1 * p
    expect(await current.isEqual(expected)).toBe(true);

    s += __1n;
    current = await ctx.combine(p, current);                // p + p
    expected = await ctx.operate(s, p);                     // 2 * p
    expect(await current.isEqual(expected)).toBe(true);

    s += __1n;
    current = await ctx.combine(p, current);                // p + (p + p)
    expected = await ctx.operate(s, p);                     // 3 * p
    expect(await current.isEqual(expected)).toBe(true);
  });
});


describe('point to bytes and back', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const p = await ctx.randomPoint();
    const pBytes = p.toBytes();
    const pBack = ctx.unpack(pBytes);
    expect(await pBack.isEqual(p)).toBe(true);
  })
});


describe('point to hex and back', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const p = await ctx.randomPoint();
    const pHex = p.toHex();
    const pBack = ctx.unhexify(pHex);
    expect(await pBack.isEqual(p)).toBe(true);
  })
});


describe('scalar validation', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const s = await ctx.randomScalar();
    const isValid = await ctx.validateScalar(s);
    expect(isValid).toBe(true);
    const t = ctx.order;
    await expect(ctx.validateScalar(t)).rejects.toThrow(
      Messages.INVALID_SCALAR
    );
  })
});


describe('bytes validation', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const b = await ctx.randomBytes();
    const isValid = await ctx.validateBytes(b);
    expect(isValid).toBe(true);
    const c = new Uint8Array([...b, 0]);
    await expect(ctx.validateBytes(c)).rejects.toThrow(
      Messages.INVALID_BYTELENGTH
    );
  })
});


describe('Keypair generation - no given secret', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const { secret, point } = await ctx.generateKeypair();
    expect(await point.isEqual(await ctx.operate(secret, ctx.generator))).toBe(true);
  })
});

describe('Keypair generation - given secret', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const scalar = await ctx.randomScalar();
    const { secret, point } = await ctx.generateKeypair(scalar);
    expect(secret).toEqual(scalar);
    expect(await point.isEqual(await ctx.operate(scalar, ctx.generator))).toBe(true);
  })
});
