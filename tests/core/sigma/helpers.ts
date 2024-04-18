import { Point, Group } from '../../../src/backend/abstract';
import { Algorithms } from '../../../src/enums';
import { Algorithm } from '../../../src/types';
import { leInt2Buff, leBuff2Int } from '../../../src/utils';
import { DlogLinear, DlogPair, DDHTuple } from '../../../src/core/sigma';

const utils = require('../../../src/utils');

const __0n = BigInt(0);
const __1n = BigInt(1);


/** Reproduce externally the Fiat-Shamir computation */
export async function computeFiatShamir<P extends Point>(
  ctx: Group<P>,
  points: Point[],
  scalars: bigint[],
  extras: Uint8Array[],
  nonce?: Uint8Array,
  algorithm?: Algorithm,
): Promise<bigint> {
  algorithm = algorithm || Algorithms.DEFAULT;
  nonce = nonce || Uint8Array.from([]);
  const { modulus, order, generator } = ctx;
  const fixedBuff = [...leInt2Buff(modulus), ...leInt2Buff(order), ...generator.toBytes()];
  const pointsBuff = points.reduce((acc: number[], p: Point) => [...acc, ...p.toBytes()], []);
  const scalarsBuff = scalars.reduce((acc: number[], s: bigint) => [...acc, ...leInt2Buff(s)], []);
  const extrasBuff = extras.reduce((acc: number[], b: Uint8Array) => [...acc, ...b], []);
  const digest = await utils.hash(
    Uint8Array.from([...fixedBuff, ...pointsBuff, ...scalarsBuff, ...extrasBuff, ...nonce]),
    { algorithm }
  );
  return (leBuff2Int(digest)) % order;
}


/** Create generic linearDlog relation with given dimensions */
export async function createLinearRelation<P extends Point>(
  ctx: Group<P>,
  opts: { m: number, n: number },
): Promise<[bigint[], DlogLinear<P>]>{
  const { randomScalar, randomPoint, neutral, operate, combine } = ctx;
  const { m, n } = opts;
  const witnesses = new Array(n);
  const vs = Array.from({ length: m }, (_, i) => neutral);
  const us = Array.from({ length: m }, (_, i) => Array.from({ length: n }, (_, j) => neutral));
  for (let j = 0; j < n; j++) {
    const xj = await randomScalar();
    for (let i = 0; i < m; i++) {
      const uij = await randomPoint();
      vs[i] = await combine(vs[i], await operate(xj, uij));
      us[i][j] = uij;
    }
    witnesses[j] = xj;
  }
  return [witnesses, { us, vs }];
}


/** Create dlog pair with non-uniform logarithm */
export async function createAndDlogPairs<P extends Point>(
  ctx: Group<P>,
  nrPairs: number,
): Promise<[bigint[], DlogPair<P>[]]>{
  const { randomScalar, randomPoint, operate } = ctx;
  const witnesses = new Array(nrPairs);
  const pairs = new Array(nrPairs);
  for (let i = 0; i < nrPairs; i++) {
    const x = await randomScalar();
    const u = await randomPoint();
    const v = await operate(x, u);
    witnesses[i] = x;
    pairs[i] = { u, v };
  }
  return [witnesses, pairs];
}


/** Creates dlog pairs with uniform logarithm */
export async function createEqDlogPairs<P extends Point>(
  ctx: Group<P>,
  nrPairs: number
): Promise<[bigint, DlogPair<P>[]]> {
  const { randomScalar, randomPoint, operate } = ctx;
  const x = await randomScalar();
  const pairs = [];
  for (let i = 0; i < nrPairs; i++) {
    const u = await randomPoint();
    const v = await operate(x, u);
    pairs.push({ u, v });
  }
  return [x, pairs];
}


/** Create single dlog pair */
export async function createDlogPair<P extends Point>(
  ctx: Group<P>,
  x?: bigint,
): Promise<[bigint, DlogPair<P>]> {
  const { randomScalar, randomPoint, operate } = ctx;
  x = x || await randomScalar();
  const u = await randomPoint();
  const v = await operate(x, u);
  return [x, { u, v }];
}


/** Create DDH-tuple */
export async function createDDHTuple<P extends Point>(
  ctx: Group<P>,
  z?: bigint
): Promise<[bigint, DDHTuple<P>]> {
  const { randomScalar, randomPoint, operate, generator: g } = ctx;
  z = z || await randomScalar();
  const u = await randomPoint();
  const v = await operate(z, g);
  const w = await operate(z, u);
  return [z, { u, v, w }];
}


/** Create point representation based on Pedersen commitment */
export async function createRepresentation<P extends Point>(
  ctx: Group<P>,
  h: P,
  s?: bigint,
  t?: bigint,
): Promise<[{ s: bigint, t: bigint }, { h: P, u: P }]> {
  const { randomScalar, operate, combine, generator: g } = ctx;
  s = s || await randomScalar();
  t = t || await randomScalar();
  const u = await combine(await operate(s, g), await operate(t, h))
  return [{ s, t }, { h, u }];
}
