import { Cryptosystem } from '../src/elgamal/system';
import { Point } from '../src/elgamal/abstract';
import { Systems, Algorithms } from '../src/enums';
import { leInt2Buff, leBuff2Int } from '../src/utils';

const elgamal = require('../src/elgamal');
const backend = require('../src/elgamal/backend');
const utils = require('../src/utils');

const __labels = Object.values(Systems);


describe('system initialization', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx1 = elgamal.initCryptosystem(label);
    const ctx2 = new Cryptosystem(backend.initGroup(label));
    expect(await ctx1.isEqual(ctx2)).toBe(true);
    expect(await ctx1.label).toEqual(label);
  });
});


describe('system initialization failure', () => {
  test('unsupported system', () => {
    const unsupported = 'unsupported';
    expect(() => elgamal.initCryptosystem(unsupported)).toThrow(
      `Unsupported system: ${unsupported}`
    );
  });
});


describe('system equality', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = elgamal.initCryptosystem(label);
    expect(await ctx.isEqual(elgamal.initCryptosystem(label))).toBe(true);
    expect(await ctx.isEqual(
      elgamal.initCryptosystem(
        label == Systems.ED25519 ?
          Systems.ED448 :
          Systems.ED25519
      )
    )).toBe(false);
  });
});


describe('fiat-shamir heuristic', () => {
  it.each(__labels)('over %s', async (label) => {
    const algorithm = Algorithms.DEFAULT;
    const ctx = elgamal.initCryptosystem(label);

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

    // Compute expected result externally
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
    const expected = await ctx.operate(digestScalar, ctx.generator);

    expect(await result.isEqual(expected)).toBe(true);
  });
});
