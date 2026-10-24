import { describe, test, mock } from 'node:test';
import assert from 'node:assert/strict';
import { each } from './utils';
import { ed25519, ristretto255 } from '@noble/curves/ed25519.js';
import { ed448, decaf448 } from '@noble/curves/ed448.js';
import { Group, Point } from 'vsslib/backend';
import { nizk } from 'vsslib/nizk';
import { Algorithms } from 'vsslib/enums';
import {
  initBackend,
  randomSecret,
  extractPublic,
  isKeypair,
  shareSecret,
  createFeldmanPackets,
  verifyFeldmanCommitments,
  derivePedersenBase,
  createPedersenPackets,
  verifyPedersenCommitments,
  createSchnorrPacket,
  combinePublicShares,
  computeLambdas,
  recoverPublic,
} from 'vsslib';
import { evalCommitments } from 'vsslib/operations/commitments';
import { resolveTestConfig } from './environ';

const { systems } = resolveTestConfig();


// Whether exp blinds secret multiplication of the generator and of any other
// point, per system: through noble, or through a base multiplication hook,
// which on decaf448 covers a generator that noble does not blind
const NATIVE: Record<string, { generator: boolean, other: boolean }> = {
  ed25519:      { generator: true,  other: false },
  ed448:        { generator: true,  other: false },
  jubjub:       { generator: true,  other: false },
  ristretto255: { generator: true,  other: false },
  decaf448:     { generator: true,  other: false },
  secp256k1:    { generator: true,  other: true },
  p256:         { generator: true,  other: true },
  p384:         { generator: true,  other: true },
  p521:         { generator: true,  other: true },
};


/** Record the scalars passed to expSecret and expPublic, the scalar lists
 * passed to multiExpPublic, and the scalars passed to exp other than from
 * within any of them */
const traceExp = <P extends Point>(ctx: Group<P>) => {
  const direct: bigint[] = [];
  const secret: bigint[] = [];
  const pub: bigint[] = [];
  const multi: bigint[][] = [];
  const { exp, expSecret, expPublic, multiExpPublic } = ctx;
  let depth = 0;
  ctx.exp = async (point, scalar) => {
    if (depth === 0) direct.push(scalar);
    return exp(point, scalar);
  };
  ctx.expSecret = async (point, scalar) => {
    secret.push(scalar);
    depth++;
    try { return await expSecret(point, scalar); } finally { depth--; }
  };
  ctx.expPublic = async (point, scalar) => {
    pub.push(scalar);
    depth++;
    try { return await expPublic(point, scalar); } finally { depth--; }
  };
  ctx.multiExpPublic = async (points, scalars) => {
    multi.push(scalars);
    depth++;
    try { return await multiExpPublic(points, scalars); } finally { depth--; }
  };
  return { direct, secret, public: pub, multi };
}


describe('noble blinding assumptions', () => {
  test('ristretto255 multiplies the ed25519 base, decaf448 not the ed448 base', () => {
    assert.equal((ristretto255.Point.BASE as any).ep, ed25519.Point.BASE);
    assert.notEqual((decaf448.Point.BASE as any).ep, ed448.Point.BASE);
  });
  test('decaf448 base is twice the ed448 base', () => {
    // The decaf448 base multiplication goes through the ed448 base for this
    const double = new decaf448.Point(ed448.Point.BASE.double());
    assert.equal(double.equals(decaf448.Point.BASE), true);
  });
});


describe('secret exponentiation', () => {
  each(systems)('agrees with exponentiation over %s', async (system) => {
    const ctx = initBackend(system);
    const points = [
      ctx.generator,
      ctx.neutral,
      await ctx.parsePoint(ctx.generator.toBytes()),
      await ctx.randomPoint(),
    ];
    const scalars = [0n, 1n, 2n, ctx.order - 1n, await ctx.randomScalar()];
    for (const point of points) {
      for (const scalar of scalars) {
        const expected = await ctx.exp(point, scalar);
        assert.equal(await (await ctx.expSecret(point, scalar)).equals(expected), true);
        assert.equal(await (await ctx.expPublic(point, scalar)).equals(expected), true);
      }
    }
  });
  each(systems)('splits the scalar unless blinded natively over %s', async (system) => {
    const ctx = initBackend(system);
    const { generator, other } = NATIVE[system];
    const cases: [Point, boolean][] = [
      [ctx.generator, generator],
      // Same element, but noble recognizes its base by identity
      [await ctx.parsePoint(ctx.generator.toBytes()), other],
      [await ctx.randomPoint(), other],
      [await ctx.hashToPoint(Uint8Array.of(1), Uint8Array.of(2)), other],
    ];
    for (const [point, native] of cases) {
      const spy = mock.method(ctx, 'randomScalar');
      const exp = mock.method(ctx, 'exp');
      try {
        await ctx.expSecret(point as any, await (ctx.randomScalar)());
        assert.equal(ctx.blindsNatively(point as any), native);
        // One sampling above, two more for the split and its blinded inversion
        assert.equal(spy.mock.callCount(), native ? 1 : 3);
        assert.equal(exp.mock.callCount(), native ? 1 : 2);
      } finally {
        spy.mock.restore();
        exp.mock.restore();
      }
    }
  });
  each(systems)('never inverts the splitting factor directly over %s', async (system) => {
    // Inversion is variable-time and would leak the factor that hides the scalar
    const ctx = initBackend(system);
    const sampled: bigint[] = [];
    const inverted: bigint[] = [];
    const randomScalar = ctx.randomScalar;
    const invertScalar = ctx.invertScalar;
    const sample = mock.method(ctx, 'randomScalar', async () => {
      const r = await randomScalar();
      sampled.push(r);
      return r;
    });
    const invert = mock.method(ctx, 'invertScalar', (x: bigint) => {
      inverted.push(x);
      return invertScalar(x);
    });
    // Force the split also where noble blinds natively
    const native = mock.method(ctx, 'blindsNatively', () => false);
    try {
      const point = await ctx.hashToPoint(Uint8Array.of(1), Uint8Array.of(2));
      for (let i = 0; i < 4; i++) await ctx.expSecret(point, await randomScalar());
    } finally {
      sample.mock.restore();
      invert.mock.restore();
      native.mock.restore();
    }
    assert.ok(inverted.length > 0);
    assert.deepEqual(inverted.filter(v => sampled.includes(v)), []);
  });
});


describe('decaf448 base multiplication', () => {
  test('agrees with noble', async () => {
    const ctx = initBackend('decaf448');
    const scalars = [1n, 2n, ctx.order - 1n, await ctx.randomScalar()];
    for (const scalar of scalars) {
      const point = await ctx.exp(ctx.generator, scalar);
      const expected = decaf448.Point.BASE.multiply(scalar);
      assert.equal((point.wrapped as any).equals(expected), true);
      assert.deepEqual(point.toBytes(), expected.toBytes());
      await ctx.validatePoint(point);
    }
    const zero = await ctx.exp(ctx.generator, 0n);
    assert.equal(await zero.equals(ctx.neutral), true);
  });
  test('is blinded by noble', async () => {
    // Otherwise blindsNatively would claim blinding that does not happen.
    // noble draws one random blind per blinded multiplication; equivalent
    // routes through any other object than the ed448 base draw none
    const ctx = initBackend('decaf448');
    const scalar = await ctx.randomScalar();
    const parsed = await ctx.parsePoint(ctx.generator.toBytes());
    const rng = mock.method(globalThis.crypto, 'getRandomValues');
    try {
      await ctx.exp(ctx.generator, scalar);
      assert.equal(rng.mock.callCount(), 1);
      // Only the generator object, as with noble's own base
      await ctx.exp(parsed, scalar);
      assert.equal(rng.mock.callCount(), 1);
    } finally {
      rng.mock.restore();
    }
  });
});


describe('secret scalars go through expSecret', () => {
  each(systems)('keys over %s', async (system) => {
    const ctx = initBackend(system);
    const { secret, publicBytes } = await randomSecret(ctx);
    const x = await ctx.parseScalar(secret);
    const trace = traceExp(ctx);
    await extractPublic(ctx, secret);
    await isKeypair(ctx, secret, publicBytes);
    await createSchnorrPacket(ctx, { value: secret, index: 1 });
    assert.deepEqual(trace.direct, []);
    assert.deepEqual(trace.multi, []);
    assert.deepEqual(trace.public, []);
    assert.equal(trace.secret.filter(s => s === x).length, 3);
  });
  each(systems)('sharing over %s', async (system) => {
    const ctx = initBackend(system);
    const { sharing } = await shareSecret(ctx, 3, 2);
    const coeffs = sharing.polynomial.coeffs;
    const trace = traceExp(ctx);
    await sharing.getPublicShares();
    await sharing.getShare(1);
    const { commitments } = await createFeldmanPackets(sharing);
    assert.deepEqual(trace.direct, []);
    assert.deepEqual(trace.multi, []);
    assert.deepEqual(trace.public, []);
    assert.ok(coeffs.every(x => trace.secret.includes(x)));
    const shares = await sharing.getSecretShares();
    trace.secret.length = 0;
    await verifyFeldmanCommitments(ctx, commitments, shares[0], 2);
    assert.deepEqual(trace.direct, []);
    assert.deepEqual(trace.multi, []);
    // Horner steps raise to the share index only
    assert.deepEqual(trace.public, [1n]);
    assert.deepEqual(trace.secret, [await ctx.parseScalar(shares[0].value)]);
  });
  each(systems)('pedersen over %s', async (system) => {
    const ctx = initBackend(system);
    const { sharing } = await shareSecret(ctx, 3, 2);
    const pedersenBase = await derivePedersenBase(ctx);
    const trace = traceExp(ctx);
    const { packets, commitments } = await createPedersenPackets(sharing, pedersenBase);
    assert.deepEqual(trace.direct, []);
    assert.deepEqual(trace.multi, []);
    assert.deepEqual(trace.public, []);
    assert.ok(sharing.polynomial.coeffs.every(x => trace.secret.includes(x)));
    trace.secret.length = 0;
    const { value, index, binding } = packets[1];
    await verifyPedersenCommitments(ctx, commitments, pedersenBase, { value, index }, binding!, 2);
    assert.deepEqual(trace.direct, []);
    assert.deepEqual(trace.multi, []);
    assert.deepEqual(trace.public, [2n]);
    assert.deepEqual(trace.secret, [
      await ctx.parseScalar(value), await ctx.parseScalar(binding!),
    ]);
  });
  each(systems)('nizk proofs over %s', async (system) => {
    const ctx = initBackend(system);
    const g = ctx.generator;
    const [x, z] = [await ctx.randomScalar(), await ctx.randomScalar()];
    const u = await ctx.exp(g, x);
    const v = await ctx.exp(g, z);
    const w = await ctx.exp(u, z);
    const trace = traceExp(ctx);
    await nizk(ctx, Algorithms.SHA256).proveDlog(z, { u, v: w });
    await nizk(ctx, Algorithms.SHA256).proveDDH(z, { u, v, w });
    assert.deepEqual(trace.direct, []);
    assert.deepEqual(trace.multi, []);
    assert.deepEqual(trace.public, []);
    // One nonce mult for dlog, one per entry of the 2x2 DDH relation
    assert.equal(trace.secret.length, 5);
  });
});


describe('public exponentiation', () => {
  each(systems)('commitment evaluation agrees with the exp-based path over %s', async (system) => {
    const ctx = initBackend(system);
    for (const threshold of [1, 2, 4]) {
      const { sharing } = await shareSecret(ctx, 6, threshold);
      const { commitments } = await createFeldmanPackets(sharing);
      for (const index of [1, 2, 6, 1000]) {
        const fast = await evalCommitments(ctx, commitments, index, threshold);
        // The default of Group.expPublic, which custom backends inherit
        const spy = mock.method(ctx, 'expPublic', ctx.exp);
        try {
          const slow = await evalCommitments(ctx, commitments, index, threshold);
          assert.equal(await fast.equals(slow), true);
        } finally {
          spy.mock.restore();
        }
        // Against g ^ f(index), which the commitments open to
        const y = sharing.polynomial.evaluate(index);
        assert.equal(await fast.equals(await ctx.exp(ctx.generator, y)), true);
      }
    }
  });
  each(systems)('public shares are combined through multiExpPublic over %s', async (system) => {
    const ctx = initBackend(system);
    const { sharing } = await shareSecret(ctx, 5, 3);
    const shares = (await sharing.getPublicShares()).filter(share => share.index !== 2);
    const trace = traceExp(ctx);
    await combinePublicShares(ctx, shares, 3);
    assert.deepEqual(trace.direct, []);
    assert.deepEqual(trace.secret, []);
    assert.deepEqual(trace.multi, [computeLambdas(ctx, [1, 3, 4, 5])]);
  });
  each(systems)('recovery combines the valid shares through multiExpPublic over %s', async (system) => {
    const ctx = initBackend(system);
    const { sharing } = await shareSecret(ctx, 5, 3);
    const packets = [];
    for (const share of await sharing.getSecretShares()) {
      packets.push(await createSchnorrPacket(ctx, share));
    }
    packets[1] = { ...packets[1], value: (await randomSecret(ctx)).publicBytes };
    const trace = traceExp(ctx);
    const { blame } = await recoverPublic(ctx, packets, 3, { errorOnInvalid: false });
    assert.deepEqual(blame.map(share => share.index), [2]);
    assert.deepEqual(trace.secret, []);
    assert.deepEqual(trace.multi, [computeLambdas(ctx, [1, 3, 4, 5])]);
  });
});
