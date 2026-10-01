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
} from 'vsslib';
import { evalCommitments } from 'vsslib/operations/commitments';
import { resolveTestConfig } from './environ';

const { systems } = resolveTestConfig();


// Whether noble blinds secret multiplication of the generator and of any
// other point, per system
const NATIVE: Record<string, { generator: boolean, other: boolean }> = {
  ed25519:      { generator: true,  other: false },
  ed448:        { generator: true,  other: false },
  jubjub:       { generator: true,  other: false },
  ristretto255: { generator: true,  other: false },
  decaf448:     { generator: false, other: false },
  secp256k1:    { generator: true,  other: true },
  p256:         { generator: true,  other: true },
  p384:         { generator: true,  other: true },
  p521:         { generator: true,  other: true },
};


/** Record the scalars passed to expSecret and expPublic, and those passed to
 * exp other than from within either */
const traceExp = <P extends Point>(ctx: Group<P>) => {
  const direct: bigint[] = [];
  const secret: bigint[] = [];
  const pub: bigint[] = [];
  const { exp, expSecret, expPublic } = ctx;
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
  return { direct, secret, public: pub };
}


describe('noble blinding assumptions', () => {
  test('ristretto255 multiplies the ed25519 base, decaf448 not the ed448 base', () => {
    expect((ristretto255.Point.BASE as any).ep).toBe(ed25519.Point.BASE);
    expect((decaf448.Point.BASE as any).ep).not.toBe(ed448.Point.BASE);
  });
});


describe('secret exponentiation', () => {
  it.each(systems)('agrees with exponentiation over %s', async (system) => {
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
        expect(await (await ctx.expSecret(point, scalar)).equals(expected)).toBe(true);
        expect(await (await ctx.expPublic(point, scalar)).equals(expected)).toBe(true);
      }
    }
  });
  it.each(systems)('splits the scalar unless blinded natively over %s', async (system) => {
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
      const spy = jest.spyOn(ctx, 'randomScalar');
      const exp = jest.spyOn(ctx, 'exp');
      try {
        await ctx.expSecret(point as any, await (ctx.randomScalar)());
        expect(ctx.blindsNatively(point as any)).toBe(native);
        // One sampling above, two more for the split and its blinded inversion
        expect(spy).toHaveBeenCalledTimes(native ? 1 : 3);
        expect(exp).toHaveBeenCalledTimes(native ? 1 : 2);
      } finally {
        spy.mockRestore();
        exp.mockRestore();
      }
    }
  });
  it.each(systems)('never inverts the splitting factor directly over %s', async (system) => {
    // Inversion is variable-time and would leak the factor that hides the scalar
    const ctx = initBackend(system);
    const sampled: bigint[] = [];
    const inverted: bigint[] = [];
    const randomScalar = ctx.randomScalar;
    const invertScalar = ctx.invertScalar;
    const sample = jest.spyOn(ctx, 'randomScalar').mockImplementation(async () => {
      const r = await randomScalar();
      sampled.push(r);
      return r;
    });
    const invert = jest.spyOn(ctx, 'invertScalar').mockImplementation((x) => {
      inverted.push(x);
      return invertScalar(x);
    });
    // Force the split also where noble blinds natively
    const native = jest.spyOn(ctx, 'blindsNatively').mockReturnValue(false);
    try {
      const point = await ctx.hashToPoint(Uint8Array.of(1), Uint8Array.of(2));
      for (let i = 0; i < 4; i++) await ctx.expSecret(point, await randomScalar());
    } finally {
      sample.mockRestore();
      invert.mockRestore();
      native.mockRestore();
    }
    expect(inverted.length).toBeGreaterThan(0);
    expect(inverted.filter(v => sampled.includes(v))).toEqual([]);
  });
});


describe('secret scalars go through expSecret', () => {
  it.each(systems)('keys over %s', async (system) => {
    const ctx = initBackend(system);
    const { secret, publicBytes } = await randomSecret(ctx);
    const x = await ctx.parseScalar(secret);
    const trace = traceExp(ctx);
    await extractPublic(ctx, secret);
    await isKeypair(ctx, secret, publicBytes);
    await createSchnorrPacket(ctx, { value: secret, index: 1 });
    expect(trace.direct).toEqual([]);
    expect(trace.public).toEqual([]);
    expect(trace.secret.filter(s => s === x)).toHaveLength(3);
  });
  it.each(systems)('sharing over %s', async (system) => {
    const ctx = initBackend(system);
    const { sharing } = await shareSecret(ctx, 3, 2);
    const coeffs = sharing.polynomial.coeffs;
    const trace = traceExp(ctx);
    await sharing.getPublicShares();
    await sharing.getShare(1);
    const { commitments } = await createFeldmanPackets(sharing);
    expect(trace.direct).toEqual([]);
    expect(trace.public).toEqual([]);
    expect(trace.secret).toEqual(expect.arrayContaining(coeffs));
    const shares = await sharing.getSecretShares();
    trace.secret.length = 0;
    await verifyFeldmanCommitments(ctx, commitments, shares[0], 2);
    expect(trace.direct).toEqual([]);
    // Horner steps raise to the share index only
    expect(trace.public).toEqual([1n]);
    expect(trace.secret).toEqual([await ctx.parseScalar(shares[0].value)]);
  });
  it.each(systems)('pedersen over %s', async (system) => {
    const ctx = initBackend(system);
    const { sharing } = await shareSecret(ctx, 3, 2);
    const pedersenBase = await derivePedersenBase(ctx);
    const trace = traceExp(ctx);
    const { packets, commitments } = await createPedersenPackets(sharing, pedersenBase);
    expect(trace.direct).toEqual([]);
    expect(trace.public).toEqual([]);
    expect(trace.secret).toEqual(expect.arrayContaining(sharing.polynomial.coeffs));
    trace.secret.length = 0;
    const { value, index, binding } = packets[1];
    await verifyPedersenCommitments(ctx, commitments, pedersenBase, { value, index }, binding!, 2);
    expect(trace.direct).toEqual([]);
    expect(trace.public).toEqual([2n]);
    expect(trace.secret).toEqual([
      await ctx.parseScalar(value), await ctx.parseScalar(binding!),
    ]);
  });
  it.each(systems)('nizk proofs over %s', async (system) => {
    const ctx = initBackend(system);
    const g = ctx.generator;
    const [x, z] = [await ctx.randomScalar(), await ctx.randomScalar()];
    const u = await ctx.exp(g, x);
    const v = await ctx.exp(g, z);
    const w = await ctx.exp(u, z);
    const trace = traceExp(ctx);
    await nizk(ctx, Algorithms.SHA256).proveDlog(z, { u, v: w });
    await nizk(ctx, Algorithms.SHA256).proveDDH(z, { u, v, w });
    expect(trace.direct).toEqual([]);
    expect(trace.public).toEqual([]);
    // One nonce mult for dlog, one per entry of the 2x2 DDH relation
    expect(trace.secret).toHaveLength(5);
  });
});


describe('public exponentiation', () => {
  it.each(systems)('commitment evaluation agrees with the exp-based path over %s', async (system) => {
    const ctx = initBackend(system);
    for (const threshold of [1, 2, 4]) {
      const { sharing } = await shareSecret(ctx, 6, threshold);
      const { commitments } = await createFeldmanPackets(sharing);
      for (const index of [1, 2, 6, 1000]) {
        const fast = await evalCommitments(ctx, commitments, index, threshold);
        // The default of Group.expPublic, which custom backends inherit
        const spy = jest.spyOn(ctx, 'expPublic').mockImplementation(ctx.exp);
        try {
          const slow = await evalCommitments(ctx, commitments, index, threshold);
          expect(await fast.equals(slow)).toBe(true);
        } finally {
          spy.mockRestore();
        }
        // Against g ^ f(index), which the commitments open to
        const y = sharing.polynomial.evaluate(index);
        expect(await fast.equals(await ctx.exp(ctx.generator, y))).toBe(true);
      }
    }
  });
});
