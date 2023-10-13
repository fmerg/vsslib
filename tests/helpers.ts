import { CryptoSystem } from '../src/elgamal/crypto';
import { Point } from '../src/elgamal/abstract';
import { Systems, Algorithms } from '../src/enums';
import { Algorithm } from '../src/types';
import { leInt2Buff, leBuff2Int } from '../src/utils';
import { DlogPair, DDHTuple } from '../src/elgamal/crypto';

const utils = require('../src/utils');


export const cartesian = (arrays: any[]): any[] => {
  if (arrays.length == 2) {
    const xs = arrays[0];
    const ys = arrays[1];
    let out = new Array(xs.length * ys.length);
    for (const [i, x] of xs.entries()) {
      for (const [j, y] of ys.entries()) {
        out[i * ys.length + j] = [x, y];
      }
    }
    return out;
  } else {
    const xs = arrays[0];
    const ys = cartesian(arrays.slice(1));
    let out = new Array(xs.length * ys.length);
    for (const [i, x] of xs.entries()) {
      for (const [j, y] of ys.entries()) {
        out[i * ys.length + j] = [x, ...y];
      }
    }
    return out;
  }
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

/** Trims trailing zeroes from number array */
export const trimZeroes = (arr: number[]): number[] => {
  let len = arr.length;
  if (len > 0) {
    while (arr[len - 1] == 0) len--;
  }
  return arr.slice(0, len);
}
