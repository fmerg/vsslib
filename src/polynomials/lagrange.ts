import { Polynomial } from './core';
import { Point, Group } from '../backend/abstract';
import { Messages } from './enums';
import { mod, modInv, Messages as utilMessages } from '../utils';
import { byteLen, randBigint } from '../utils';
import { Label } from '../types';
const backend = require('../backend');


const __0n = BigInt(0);
const __1n = BigInt(1);

export type XYTuple = [bigint, bigint] | [number, number];


export class Lagrange<P extends Point> extends Polynomial<P> {
  _xs: bigint[];
  _ys: bigint[];
  _ws: bigint[];

  constructor(ctx: Group<P>, points: [bigint, bigint][]) {
    const k = points.length
    const { order } = ctx;
    if (k > order) throw new Error(Messages.INTERPOLATION_NR_POINTS_EXCEEDS_ORDER);
    const xs = new Array(k);
    const ys = new Array(k);
    const ws = new Array(k);
    let coeffs = new Array(k).fill(__0n);
    for (let j = 0; j < k; j++) {
      const [xj, yj] = points[j];
      let w = __1n;
      let pj = [__1n];
      for (let i = 0; i < k; i++) {
        if (i !== j) {
          const [xi, _] = points[i];
          w *= xj - xi;
          const len = pj.length;
          let _pj = new Array(len + 1);
          _pj[0] = - xi * pj[0];
          for (let a = 0; a < len - 1; a++) {
            _pj[a + 1] = pj[a] - xi * pj[a + 1];
          }
          _pj[len] = pj[len - 1];
          pj = _pj;
        }
      }
      let wj;
      try { wj = modInv(w, order); } catch (err: any) {
        if (err.message == utilMessages.INVERSE_NOT_EXISTS) throw new Error(
          Messages.INTERPOLATION_NON_DISTINCT_XS
        );
        else throw err;
      }
      xs[j] = xj;
      ys[j] = yj;
      ws[j] = wj;
      const fj = yj * wj;
      coeffs = coeffs.map((c, i) => c + fj * pj[i]);
    }
    super(ctx, coeffs);
    this._xs = xs;
    this._ys = ys;
    this._ws = ws;
  }

  static async interpolate<Q extends Point>(ctx: Group<Q>, points: XYTuple[]): Promise<Lagrange<Q>> {
    return new Lagrange(ctx, points.map(([x, y]) => [BigInt(x), BigInt(y)]));
  }

  evaluate = (value: bigint | number): bigint => {
    const { _xs: xs, _ys: ys, _ws: ws, _order: order } = this;
    const x = BigInt(value);
    let [a, b, c] = [__0n, __0n, __0n];
    for (let i = 0; i < xs.length; i++) {
      if (mod(x, order) === mod(xs[i], order)) {
        return mod(ys[i], order);
      };
      a = ws[i] * modInv(x - xs[i], order);
      b += a * ys[i];
      c += a;
    }
    return mod(b * modInv(c, order), order);
  }
}
