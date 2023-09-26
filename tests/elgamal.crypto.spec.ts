import { CryptoSystem } from '../src/elgamal/crypto';
import { Point } from '../src/elgamal/abstract';
import { Systems, Algorithms } from '../src/enums';
import { Algorithm } from '../src/types';
import { leInt2Buff, leBuff2Int } from '../src/utils';

const elgamal = require('../src/elgamal');
const backend = require('../src/elgamal/backend');
const utils = require('../src/utils');

const __labels      = Object.values(Systems);
const __algorithms  = Object.values(Algorithms);


describe('crypto initialization', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx1 = elgamal.initCrypto(label);
    const ctx2 = new CryptoSystem(backend.initGroup(label));
    expect(await ctx1.isEqual(ctx2)).toBe(true);
    expect(await ctx1.label).toEqual(label);
  });
});


describe('crypto initialization failure', () => {
  test('unsupported crypto', () => {
    const unsupported = 'unsupported';
    expect(() => elgamal.initCrypto(unsupported)).toThrow(
      `Unsupported crypto: ${unsupported}`
    );
  });
});


describe('crypto equality', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = elgamal.initCrypto(label);
    expect(await ctx.isEqual(elgamal.initCrypto(label))).toBe(true);
    expect(await ctx.isEqual(
      elgamal.initCrypto(
        label == Systems.ED25519 ?
          Systems.ED448 :
          Systems.ED25519
      )
    )).toBe(false);
  });
});


describe('fiat-shamir heuristic', () => {
  // Helper for reproducing externally the fiat-shamir computation
  const computeFiatShamir = async (
    ctx: CryptoSystem,
    scalars: bigint[],
    points: Point[],
    algorithm: Algorithm | undefined,
  ): Promise<Point> => {
    const fixedBuff = [
      leInt2Buff(ctx.modulus),
      leInt2Buff(ctx.order),
      ctx.generator.toBytes(),
    ].reduce(
      (acc: number[], curr: Uint8Array) => [...acc, ...curr], []
    )
    const scalarsBuff = scalars.reduce(
      (acc: number[], s: bigint) => [...acc, ...leInt2Buff(s)], []
    );
    const pointsBuff = points.reduce(
      (acc: number[], p: Point) => [...acc, ...p.toBytes()], []
    );
    const buffer = [fixedBuff, scalarsBuff, pointsBuff].reduce(
      (acc, curr) => [...acc, ...curr], []
    );
    const digest = await utils.hash(
      new Uint8Array(
        [fixedBuff, scalarsBuff, pointsBuff].reduce(
          (acc, curr) => [...acc, ...curr], []
        )
      ),
      { algorithm }
    );
    const digestScalar = (leBuff2Int(digest) as bigint) % ctx.order;
    return ctx.operate(digestScalar, ctx.generator);
  }

  const combinations: any[] = [];
  for (const label of __labels) {
    for (const algorithm of [...__algorithms, undefined]) {
      combinations.push([label, algorithm]);
    }
  }
  it.each(combinations)('over %s/%s', async (label, algorithm) => {
    const ctx = elgamal.initCrypto(label);
    const scalars = [
      await ctx.randomScalar(),
      await ctx.randomScalar(),
    ];
    const points = [
      await ctx.randomPoint(),
      await ctx.randomPoint(),
      await ctx.randomPoint(),
    ]
    const result = await ctx.fiatShamir(scalars, points, algorithm);
    expect(await result.isEqual(await computeFiatShamir(
      ctx, scalars, points, algorithm
    ))).toBe(true);
  });
});
