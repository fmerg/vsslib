import { Point, Group } from 'vsslib/backend';
import { mod, modInv } from 'vsslib/arith';
import { FieldPolynomial } from 'vsslib/polynomials';
import { InverseNotExists, InterpolationError } from 'vsslib/errors';


const __0n = BigInt(0);
const __1n = BigInt(1);

export type XYPoint = [bigint, bigint] | [number, number];

export class LagrangePolynomial<P extends Point> extends FieldPolynomial<P> {
  xs: bigint[];
  ys: bigint[];
  ws: bigint[];

  constructor(ctx: Group<P>, points: [bigint, bigint][]) {
    const k = points.length;
    const order = ctx.order;
    if (k > order) throw new InterpolationError(
      'Number of provided points exceeds order'
    );

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
          const _pj = new Array(len + 1);
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
        if (err instanceof InverseNotExists) throw new InterpolationError(
          'Not all provided x\'s are distinct modulo order'
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
    this.xs = xs;
    this.ys = ys;
    this.ws = ws;
  }

  evaluate = (value: bigint | number): bigint => {
    const { xs, ys, ws, order } = this;
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


export class LagrangeInterpolator<P extends Point> {
  ctx: Group<P>;

  constructor(ctx: Group<P>) {
    this.ctx = ctx;
  }

  interpolate = async (points: XYPoint[]) => new LagrangePolynomial(
    this.ctx, points.map(([x, y]: XYPoint)=> [BigInt(x), BigInt(y)])
  )
}

export default function<P extends Point>(ctx: Group<P>) {
  return new LagrangeInterpolator(ctx);
}
