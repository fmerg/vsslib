import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { each } from './utils';
import { initBackend } from 'vsslib/backend';
import { resolveTestConfig } from './environ';
import { fixtures } from './systems';

const __0n = BigInt(0)
const __1n = BigInt(1)

const { systems } = resolveTestConfig();


describe('group initialization - success', () => {
  each(systems)('over %s', async (system) => {
    const ctx = initBackend(system);
    assert.equal(ctx.system, system);
  });
})

describe('group initialization - failure', () => {
  test('unsupported group', () => {
    const system = 'foo';
    assert.throws(() => initBackend(system), { message: `Unsupported group: ${system}` })
  })
})

describe('neutral element', () => {
  each(systems)('over %s', async (system) => {
    const ctx = initBackend(system);
    await ctx.validatePoint(ctx.neutral);
    const neutral = await ctx.exp(ctx.generator, __0n);
    assert.equal(await neutral.equals(ctx.neutral), true);
  });
});

describe('group generator', () => {
  each(systems)('over %s', async (system) => {
    const ctx = initBackend(system);
    await ctx.validatePoint(ctx.generator);
    const generator = await ctx.exp(ctx.generator, __1n);
    assert.equal(await generator.equals(ctx.generator), true);
  });
});

describe('group operation', () => {
  each(systems)('neutral element - over %s', async (system) => {
    const ctx = initBackend(system);
    const p = await ctx.randomPoint();
    const q = await ctx.operate(p, ctx.neutral);
    assert.equal(await q.equals(p), true);
    const u = await ctx.operate(ctx.neutral, p);
    assert.equal(await u.equals(p), true);
  });
  each(systems)('random pair - over %s', async (system) => {
    const ctx = initBackend(system);
    const r = await ctx.randomScalar();
    const s = await ctx.randomScalar();
    const p = await ctx.exp(ctx.generator, r);
    const q = await ctx.exp(ctx.generator, s);
    const u = await ctx.operate(p, q);
    const t = (r + s) % ctx.order;
    const v = await ctx.exp(ctx.generator, t);
    assert.equal(await v.equals(u), true);
  });
});

describe('inverse', () => {
  each(systems)('neutral - over %s', async (system) => {
    const ctx = initBackend(system);
    const neutInv = await ctx.invert(ctx.neutral);
    assert.equal(await neutInv.equals(ctx.neutral), true);
    const neutral = await ctx.operate(ctx.neutral, neutInv);
    assert.equal(await neutral.equals(ctx.neutral), true);
  });
  each(systems)('generator - over %s', async (system) => {
    const ctx = initBackend(system);
    const minusOne = ctx.order - __1n;             // TODO: scalar -1
    const expected = await ctx.exp(ctx.generator, minusOne);
    const genInv = await ctx.invert(ctx.generator);
    assert.equal(await genInv.equals(expected), true);
    const neutral = await ctx.operate(ctx.generator, genInv);
    assert.equal(await neutral.equals(ctx.neutral), true);
  });
  each(systems)('random point - over %s', async (system) => {
    const ctx = initBackend(system);
    const r = await ctx.randomScalar();
    const p = await ctx.exp(ctx.generator, r);
    const pInv = await ctx.invert(p);
    const minusR = ctx.order - BigInt(r);
    const expected = await ctx.exp(ctx.generator, minusR);
    assert.equal(await pInv.equals(expected), true);
    const neutral = await ctx.operate(p, pInv);
    assert.equal(await neutral.equals(ctx.neutral), true);
  });
});

describe('exponentiation', () => {
  each(systems)('generator - over %s', async (system) => {
    const ctx = initBackend(system);

    let expected = await ctx.exp(ctx.generator, __0n)
    assert.equal(await ctx.neutral.equals(expected), true);
    expected = await ctx.exp(ctx.generator, __0n);
    assert.equal(await ctx.neutral.equals(expected), true);

    const s = await ctx.randomScalar();
    const p = await ctx.exp(ctx.generator, s);
    const q = await ctx.exp(ctx.generator, s);
    assert.equal(await q.equals(p), true);
  })
  each(systems)('random point - over %s', async (system) => {
    const ctx = initBackend(system);
    let s: bigint;
    let current: any;
    let expected: any

    const p = await ctx.randomPoint();                    // p

    s = __0n;
    current = ctx.neutral;                                // 0
    expected = await ctx.exp(p, s);                       // 0 * p
    assert.equal(await current.equals(expected), true);

    s += __1n;
    current = p;                                          // p
    expected = await ctx.exp(p, s);                       // 1 * p
    assert.equal(await current.equals(expected), true);

    s += __1n;
    current = await ctx.operate(p, current);              // p + p
    expected = await ctx.exp(p, s);                       // 2 * p
    assert.equal(await current.equals(expected), true);

    s += __1n;
    current = await ctx.operate(p, current);              // p + (p + p)
    expected = await ctx.exp(p, s);                       // 3 * p
    assert.equal(await current.equals(expected), true);
  });
});

describe('point to bytes and back', () => {
  each(systems)('success over %s', async (system) => {
    const ctx = initBackend(system);
    const p = await ctx.randomPoint();
    const buff = p.toBytes();
    const pBack = ctx.bytesToPoint(buff)
    assert.equal(await pBack.equals(p), true);
  })
  each(systems)('failure over %s', async (system) => {
    const ctx = initBackend(system);
    const buff = Uint8Array.from(Buffer.from('foo'));
    assert.throws(() => ctx.bytesToPoint(buff), /bad encoding:/);
  })
});

describe('scalar validation', () => {
  each(systems)('over %s', async (system) => {
    const ctx = initBackend(system);
    const s = await ctx.randomScalar();
    const isValid = await ctx.validateScalar(s);
    assert.equal(isValid, true);
    const t = ctx.order;
    await assert.rejects(ctx.validateScalar(t), /Scalar not in range/);
  })
});

describe('canonical encoding', () => {
  each(systems)('roundtrip over %s', async (system) => {
    const ctx = initBackend(system);
    const points = [ctx.neutral, ctx.generator, await ctx.randomPoint()];
    for (const p of points) {
      const bytes = p.toBytes();
      const q = await ctx.parsePoint(bytes);
      assert.equal(await q.equals(p), true);
      assert.deepEqual(q.toBytes(), bytes);
    }
  });
  each(systems)('known non-canonical encodings rejected over %s', async (system) => {
    const ctx = initBackend(system);
    for (const bytes of fixtures[system].nonCanonicalPoints) {
      await assert.rejects(ctx.parsePoint(bytes), /Invalid point provided/);
    }
  });
  each(systems)('non-canonical encodings rejected over %s', async (system) => {
    // A backend decoder that ignores a trailing byte must not let two
    // encodings of the same element through
    const ctx = initBackend(system);
    const decode = ctx.bytesToPoint;
    ctx.bytesToPoint = (bytes: Uint8Array) => decode(bytes.slice(0, -1));
    const bytes = Uint8Array.from([...ctx.generator.toBytes(), 0]);
    await assert.rejects(ctx.parsePoint(bytes), /not canonical/);
  });
});
