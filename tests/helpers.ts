import { Point, Group } from '../src/backend/abstract';
import { Systems, Algorithms } from '../src/enums';
import { Algorithm } from '../src/types';
import { leInt2Buff, leBuff2Int } from '../src/utils';
import { LinearRelation, DlogPair, DDHTuple } from '../src/sigma';
import { XYPoint, BasePolynomial } from '../src/polynomials';
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


/** Trim trailing zeroes from number array */
export const trimZeroes = (arr: number[]): number[] => {
  let len = arr.length;
  if (len > 0) {
    while (arr[len - 1] == 0) len--;
  }
  return arr.slice(0, len);
}


/** Textbook polynomials interpolation. Number of points must not exceed order.
 */
export const interpolate = (points: XYPoint[], opts: { order: bigint }): BasePolynomial => {
  const order = BigInt(opts.order);
  const castPoints = points.map(([x, y]) => [BigInt(x), BigInt(y)]);
  let poly = BasePolynomial.zero({ order });
  for (let j = 0; j < castPoints.length; j++) {
    const [xj, yj] = castPoints[j];
    let w = __1n;
    let pj = new BasePolynomial([__1n], order);
    for (let i = 0; i < castPoints.length; i++) {
      if (i !== j) {
        const [xi, _] = castPoints[i];
        w *= xj - xi;
        pj = pj.mult(new BasePolynomial([-xi, __1n], order))
      }
    }
    const wInv = utils.modInv(w, order);
    pj = pj.multScalar(yj * wInv)
    poly = poly.add(pj);
  }

  return poly;
}
