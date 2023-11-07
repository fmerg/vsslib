import { Point, Group } from '../src/backend/abstract';
import { Systems, Algorithms } from '../src/enums';
import { Algorithm } from '../src/types';
import { leInt2Buff, leBuff2Int } from '../src/utils';
import { LinearRelation, DlogPair, DDHTuple } from '../src/sigma';
import { XYPoint, Polynomial } from '../src/lagrange';
import { Permutation, PowerSet } from "js-combinatorics";

const utils = require('../src/utils');

const __0n = BigInt(0);
const __1n = BigInt(1);


/** Powerset of the provided collection **/
export const powerSet = (array: any[]): any[] => [...PowerSet.of(array)];


/** Permutations of the provided collection **/
export const permutations = (array: any[]): any[] => [...Permutation.of(array)];


/** Union of sets of permutations of each member of the powerset of
* the provided collection */
export const partialPermutations = (array: any[], minSize = 0, maxSize = array.length): any[] => {
  const out = powerSet(array).reduce(
    (acc: any[], comb: any[]) => acc = acc.concat(permutations(comb)), []
  );
  return out.filter((perm: any[]) => perm.length >= minSize && perm.length <= maxSize);
}


/** Cartesian product of the provided arrays */
export const cartesian = (arrays: any[]): any[] => {
  const xs = arrays[0];
  const ys = arrays.length > 2 ? cartesian(arrays.slice(1)) : arrays[1].map((a: any[]) => [a]);
  let out = new Array(xs.length * ys.length);
  for (const [i, x] of xs.entries()) {
    for (const [j, y] of ys.entries()) {
      out[i * ys.length + j] = [x, ...y];
    }
  }
  return out;
}


/** Reproduces externally the fiat-shamir computation */
export async function computeFiatShamir<P extends Point>(
  ctx: Group<P>,
  points: Point[],
  scalars: bigint[],
  opts?: { algorithm?: Algorithm, nonce?: Uint8Array },
): Promise<bigint> {
  const algorithm = opts ? (opts.algorithm || Algorithms.DEFAULT) : Algorithms.DEFAULT;
  const nonce = opts ? (opts.nonce || new Uint8Array()) : new Uint8Array([]);
  const { modulus, order, generator } = ctx;
  const fixedBuff = [...leInt2Buff(modulus), ...leInt2Buff(order), ...generator.toBytes()];
  const pointsBuff = points.reduce((acc: number[], p: Point) => [...acc, ...p.toBytes()], []);
  const scalarsBuff = scalars.reduce((acc: number[], s: bigint) => [...acc, ...leInt2Buff(s)], []);
  const digest = await utils.hash(
    new Uint8Array([...fixedBuff, ...pointsBuff, ...scalarsBuff, ...nonce]),
    { algorithm }
  );
  return (leBuff2Int(digest)) % order;
}



export async function createLinearRelation<P extends Point>(
  ctx: Group<P>,
  opts: { m: number, n: number },
): Promise<[bigint[], LinearRelation<P>]>{
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


/** Create point representation */
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


/** Trim trailing zeroes from number array */
export const trimZeroes = (arr: number[]): number[] => {
  let len = arr.length;
  if (len > 0) {
    while (arr[len - 1] == 0) len--;
  }
  return arr.slice(0, len);
}


/** Textbook lagrange interpolation. Number of points must not exceed order.
 */
export const interpolate = (points: XYPoint[], opts: { order: bigint }): Polynomial => {
  const order = BigInt(opts.order);
  const castPoints = points.map(([x, y]) => [BigInt(x), BigInt(y)]);
  let poly = Polynomial.zero({ order });
  for (let j = 0; j < castPoints.length; j++) {
    const [xj, yj] = castPoints[j];
    let w = __1n;
    let pj = new Polynomial([__1n], order);
    for (let i = 0; i < castPoints.length; i++) {
      if (i !== j) {
        const [xi, _] = castPoints[i];
        w *= xj - xi;
        pj = pj.mult(new Polynomial([-xi, __1n], order))
      }
    }
    const wInv = utils.modInv(w, order);
    pj = pj.multScalar(yj * wInv)
    poly = poly.add(pj);
  }

  return poly;
}
