import { CryptoSystem } from '../src/elgamal/crypto';
import { Point } from '../src/elgamal/abstract';
import { Systems, Algorithms } from '../src/enums';
import { Algorithm } from '../src/types';
import { leInt2Buff, leBuff2Int } from '../src/utils';
import { DlogPair, DDHTuple } from '../src/elgamal/crypto';

const utils = require('../src/utils');


/** Make cartesian product of provided arrays */
export const cartesian = (arr1: any[], arr2: any[]): any[] => {
  const out = [];
  for (const c1 of arr1) {
    for (const c2 of arr2) {
      out.push([c1, c2]);
    }
  }
  return out;
}


/** Reproduces externally the fiat-shamir computation */
export const computeFiatShamir = async (
  ctx: CryptoSystem,
  points: Point[],
  scalars: bigint[],
  algorithm: Algorithm | undefined,
): Promise<bigint> => {
  const fixedBuff = [
    leInt2Buff(ctx.modulus),
    leInt2Buff(ctx.order),
    ctx.generator.toBytes(),
  ].reduce(
    (acc: number[], curr: Uint8Array) => [...acc, ...curr], []
  )
  const pointsBuff = points.reduce(
    (acc: number[], p: Point) => [...acc, ...p.toBytes()], []
  );
  const scalarsBuff = scalars.reduce(
    (acc: number[], s: bigint) => [...acc, ...leInt2Buff(s)], []
  );
  const buffer = [fixedBuff, scalarsBuff, pointsBuff].reduce(
    (acc, curr) => [...acc, ...curr], []
  );
  const digest = await utils.hash(
    new Uint8Array(
      [fixedBuff, pointsBuff, scalarsBuff].reduce(
        (acc, curr) => [...acc, ...curr], []
      )
    ),
    { algorithm }
  );
  return (leBuff2Int(digest) as bigint) % ctx.order;
}


/** Creates dlog pairs with uniform logarithm */
export const createDlogPairs = async (ctx: CryptoSystem, dlog: bigint, nrPairs: number): Promise<DlogPair[]> => {
  const us = [];
  for (let i = 0; i < nrPairs; i++) {
    us.push(await ctx.randomPoint());
  }

  const pairs = [];
  for (const u of us) {
    pairs.push({
      u,
      v: await ctx.operate(dlog, u),
    });
  }

  return pairs;
}


/** Create DDH-tuples */
export const createDDH = async (ctx: CryptoSystem, dlog?: bigint): Promise<{ dlog: bigint, ddh: DDHTuple }> => {
  dlog = dlog || await ctx.randomScalar();

  const u = await ctx.randomPoint();
  const v = await ctx.operate(dlog, ctx.generator);
  const w = await ctx.operate(dlog, u);

  return { dlog, ddh: { u, v, w } };
}
