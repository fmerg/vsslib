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
  const fixedBuff = [...leInt2Buff(ctx.modulus), ...leInt2Buff(ctx.order), ...ctx.generator.toBytes()];
  const pointsBuff = points.reduce((acc: number[], p: Point) => [...acc, ...p.toBytes()], []);
  const scalarsBuff = scalars.reduce((acc: number[], s: bigint) => [...acc, ...leInt2Buff(s)], []);
  const digest = await utils.hash(
    new Uint8Array([...fixedBuff, ...pointsBuff, ...scalarsBuff]),
    { algorithm }
  );
  return (leBuff2Int(digest) as bigint) % ctx.order;
}


/** Creates dlog pairs with uniform logarithm */
export const createDlogPairs = async (ctx: CryptoSystem, z: bigint, nrPairs: number): Promise<DlogPair[]> => {
  const pairs = [];
  for (let i = 0; i < nrPairs; i++) {
    const u = await ctx.randomPoint();
    const v = await ctx.operate(z, u);
    pairs.push({ u, v });
  }
  return pairs;
}


/** Create DDH-tuples */
export const createDDH = async (ctx: CryptoSystem, z?: bigint): Promise<{ z: bigint, ddh: DDHTuple }> => {
  z = z || await ctx.randomScalar();

  const u = await ctx.randomPoint();
  const v = await ctx.operate(z, ctx.generator);
  const w = await ctx.operate(z, u);

  return { z, ddh: { u, v, w } };
}
