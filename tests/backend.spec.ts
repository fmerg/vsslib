import { describe, test, mock } from 'node:test';
import assert from 'node:assert/strict';
import { each } from './utils';
import { initBackend, Group } from 'vsslib/backend';
import type { EcGroup, EcPoint } from 'vsslib/backend';
import { InvalidInput } from 'vsslib';
import { resolveTestConfig } from './environ';
import { fixtures } from './systems';
import { inheriting } from './helpers';

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




describe('public multi-exponentiation', () => {
  // Around the cutoffs of Pippenger's method, 4 and 16 on secp256k1
  const sizes = [0, 1, 2, 3, 4, 5, 15, 16, 17, 40];
  each(systems)('agrees with exponentiation over %s', async (system) => {
    const ctx = initBackend(system);
    const groups = [ctx, inheriting(ctx)];
    for (const k of sizes) {
      const points = [];
      const scalars = [];
      for (let i = 0; i < k; i++) {
        points.push(await ctx.randomPoint());
        scalars.push(await ctx.randomScalar());
      }
      // Edge cases, kept within the k points
      const special: [EcPoint, bigint][] = [
        [ctx.generator, ctx.order - __1n],
        [ctx.neutral, await ctx.randomScalar()],
        [await ctx.randomPoint(), __0n],
        [await ctx.randomPoint(), __1n],
      ];
      for (const [i, [point, scalar]] of special.slice(0, k).entries()) {
        points[i] = point;
        scalars[i] = scalar;
      }
      let expected = ctx.neutral;
      for (let i = 0; i < k; i++) {
        expected = await ctx.operate(expected, await ctx.exp(points[i], scalars[i]));
      }
      for (const group of groups) {
        const result = await group.multiExpPublic(points, scalars);
        assert.equal(await result.equals(expected), true, `k = ${k}`);
      }
    }
  });
  each(systems)('rejects incompatible lengths over %s', async (system) => {
    const ctx = initBackend(system);
    for (const group of [ctx, inheriting(ctx)]) {
      const points = [ctx.generator, await ctx.randomPoint()];
      await assert.rejects(group.multiExpPublic(points, [__1n]), InvalidInput);
      await assert.rejects(group.multiExpPublic([], [__1n]), /Incompatible lengths/);
    }
  });
  each(systems)('rejects scalars out of range over %s', async (system) => {
    // On both sides of the cutoffs, where noble would throw errors of its own
    const ctx = initBackend(system);
    for (const group of [ctx, inheriting(ctx)]) {
      for (const k of [1, 3, 4, 16, 20]) {
        const points = [];
        const scalars = [];
        for (let i = 0; i < k; i++) {
          points.push(await ctx.randomPoint());
          scalars.push(await ctx.randomScalar());
        }
        for (const bad of [ctx.order, ctx.order + __1n, -__1n]) {
          const last = [...scalars.slice(0, -1), bad];
          await assert.rejects(
            group.multiExpPublic(points, last), { name: 'InvalidInput', message: /not in range/ }
          );
        }
      }
    }
  });
});


describe('base precomputation', () => {
  each(systems)('returns the point and keeps exponentiation over %s', async (system) => {
    const ctx = initBackend(system);
    const bytes = (await ctx.hashToPoint(Uint8Array.of(1), Uint8Array.of(2))).toBytes();
    const fresh = await ctx.parsePoint(bytes);
    const scalars = [__0n, __1n, BigInt(2), ctx.order - __1n, await ctx.randomScalar()];
    for (const group of [ctx, inheriting(ctx)]) {
      const point = await ctx.parsePoint(bytes);
      const base = group.precomputeBase(point);
      assert.equal(base, point);
      for (const scalar of scalars) {
        const expected = (await ctx.exp(fresh, scalar)).toBytes();
        for (const exp of [group.exp, group.expSecret, group.expPublic]) {
          assert.deepEqual((await exp(base, scalar)).toBytes(), expected);
        }
      }
    }
  });
  each(systems)('leaves the generator and the neutral element as they are over %s', async (system) => {
    // A new window would drop noble's table for its base
    const ctx = initBackend(system);
    const scalar = await ctx.randomScalar();
    const expected = (await ctx.exp(ctx.generator, scalar)).toBytes();
    assert.equal(ctx.precomputeBase(ctx.generator), ctx.generator);
    assert.equal(ctx.precomputeBase(ctx.neutral), ctx.neutral);
    assert.deepEqual((await ctx.expSecret(ctx.generator, scalar)).toBytes(), expected);
    assert.equal(await (await ctx.exp(ctx.neutral, scalar)).equals(ctx.neutral), true);
  });
});


/** A backend written with methods only, as a plain JavaScript or foreign
 * backend would be, delegating to a built-in group */
const methodsOnly = (ctx: EcGroup) => {
  class Methods extends Group<EcPoint> {
    async validatePoint(point: EcPoint): Promise<boolean> {
      return this.order === ctx.order && ctx.validatePoint(point);
    }
    async exp(point: EcPoint, scalar: bigint): Promise<EcPoint> { return ctx.exp(point, scalar); }
    async operate(lhs: EcPoint, rhs: EcPoint): Promise<EcPoint> { return ctx.operate(lhs, rhs); }
    async invert(point: EcPoint): Promise<EcPoint> { return ctx.invert(point); }
    bytesToPoint(bytes: Uint8Array): EcPoint { return ctx.bytesToPoint(bytes); }
    async hashToPoint(msg: Uint8Array, dst: Uint8Array): Promise<EcPoint> {
      return ctx.hashToPoint(msg, dst);
    }
  }
  return Methods;
}


describe('custom backends', () => {
  each(systems)('may define every member as a method over %s', async (system) => {
    const ctx = initBackend(system);
    const Methods = methodsOnly(ctx);
    const group = new Methods(ctx.system, ctx.modulus, ctx.order, ctx.generator, ctx.neutral);
    const bytes = (await ctx.randomPoint()).toBytes();
    // Destructured, as the library does with some members
    const { parsePoint, parseCurvePoint, randomPoint, expSecret } = group;
    for (const parse of [parsePoint, parseCurvePoint]) {
      assert.deepEqual((await parse(bytes)).toBytes(), bytes);
      for (const invalid of fixtures[system].nonCanonicalPoints) {
        await assert.rejects(parse(invalid), InvalidInput);
      }
    }
    const scalar = await group.randomScalar();
    const expected = (await ctx.exp(ctx.generator, scalar)).toBytes();
    assert.deepEqual((await expSecret(group.generator, scalar)).toBytes(), expected);
    await group.validatePoint(await randomPoint());
  });
  each(systems)('may override defaults as methods or properties over %s', async (system) => {
    const ctx = initBackend(system);
    const Methods = methodsOnly(ctx);
    const calls: string[] = [];
    class ByMethod extends Methods {
      async expPublic(point: EcPoint, scalar: bigint): Promise<EcPoint> {
        calls.push('method');
        return this.exp(point, scalar);
      }
    }
    class ByProperty extends Methods {
      expPublic = async (point: EcPoint, scalar: bigint): Promise<EcPoint> => {
        calls.push('property');
        return this.exp(point, scalar);
      }
    }
    for (const [Cls, label] of [[ByMethod, 'method'], [ByProperty, 'property']] as const) {
      const group = new Cls(ctx.system, ctx.modulus, ctx.order, ctx.generator, ctx.neutral);
      calls.length = 0;
      const { expPublic, multiExpPublic } = group;
      await expPublic(group.generator, 5n);
      // The default multiExpPublic reaches the override through this
      await multiExpPublic([group.generator, group.generator], [2n, 3n]);
      assert.deepEqual(calls, [label, label, label]);
    }
  });
  each(systems)('members stay mockable over %s', async (system) => {
    // The constructor binds members as own properties, which mocks replace
    const ctx = initBackend(system);
    const group = new (methodsOnly(ctx))(ctx.system, ctx.modulus, ctx.order, ctx.generator, ctx.neutral);
    const random = mock.method(group, 'randomScalar', async () => 7n);
    assert.deepEqual(await group.generateSecret(), group.scalarToBytes(7n));
    assert.equal(random.mock.callCount(), 1);
    random.mock.restore();
  });
});
