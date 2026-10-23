import { Point, Group } from './backend';
import { mod, modInv, modInvBatch, REDUCTION_MARGIN } from './arith';
import { FieldPolynomial } from './polynomials';
import { NoInverseError, InterpolationError, InvalidInput } from './errors';
import { validateIndexes } from './indexes';


export type XYPoint = [bigint, bigint] | [number, number];


/** Reduction modulo `order` of values that outgrew it by REDUCTION_MARGIN bits */
function reducer(order: bigint): (m: bigint) => bigint {
  const high = order << REDUCTION_MARGIN;
  const low = -high;
  return (m: bigint) => m >= high || m <= low ? m % order : m;
}

/** Ensure that `indexes` are valid share indexes below `order`, so that they
 * and their differences are invertible; throws InvalidInput otherwise */
function validateLambdaIndexes(indexes: number[], order: bigint): void {
  validateIndexes(indexes);
  for (const index of indexes) {
    if (!(BigInt(index) < order)) throw new InvalidInput(
      `Index not below the group order: ${index}`
    );
  }
}


/** Lagrange coefficient at zero of `index` with respect to `indexes`, as
 * the product of the indexes over the product of their differences, with a
 * single inversion */
export function computeLambda<P extends Point>(
  ctx: Group<P>,
  index: number,
  indexes: number[]
): bigint {
  const order = ctx.order;
  validateLambdaIndexes(indexes, order);
  if (!indexes.includes(index)) throw new InvalidInput(
    `Index not included in indexes: ${index}`
  );
  const reduce = reducer(order);
  let numerator = 1n;
  let denominator = 1n;
  for (const j of indexes) {
    if (j !== index) {
      numerator = reduce(numerator * BigInt(j));
      denominator = reduce(denominator * BigInt(j - index));
    }
  }
  return mod(numerator * modInv(denominator, order), order);
}


/** Lagrange coefficients at zero of all `indexes`, in the same order. Each
 * is the product N of all indexes over x_i times the product of differences
 * D_i, so that a single batch inversion serves all of them */
export function computeLambdas<P extends Point>(
  ctx: Group<P>,
  indexes: number[]
): bigint[] {
  const order = ctx.order;
  validateLambdaIndexes(indexes, order);
  const reduce = reducer(order);
  let numerator = 1n;
  for (const x of indexes) numerator = reduce(numerator * BigInt(x));
  const denominators = indexes.map(xi => {
    let d = BigInt(xi);
    for (const xj of indexes) {
      if (xj !== xi) d = reduce(d * BigInt(xj - xi));
    }
    return d;
  });
  return modInvBatch(denominators, order).map(w => mod(numerator * w, order));
}


/** @internal Same as computeLambda, inverting each difference separately;
 * reference for computeLambda and computeLambdas */
export function computeLambdaNaive<P extends Point>(
  ctx: Group<P>,
  index: number,
  indexes: number[]
): bigint {
  validateIndexes(indexes);
  if (!indexes.includes(index)) throw new InvalidInput(
    `Index not included in indexes: ${index}`
  );
  const order = ctx.order;
  const i = index;
  let acc = 1n;
  indexes.forEach(j => {
    if (i != j) {
      const curr = BigInt(j) * modInv(BigInt(j - i), order);
      acc = mod(acc * curr, order);
    }
  });
  return acc;
}


/** @internal Numerators (coefficients in ascending order) and denominators of
 * the Lagrange basis polynomials over `xs`, modulo `order`. Expands the
 * product of all (x - x_i) once and divides it by each (x - x_j) */
export function expandBasis(xs: bigint[], order: bigint): {
  numerators: bigint[][],
  denominators: bigint[],
} {
  const k = xs.length;
  // Coefficients of the product of all (x - x_i)
  let master = [1n];
  for (const xi of xs) {
    const next = new Array(master.length + 1);
    next[0] = mod(- xi * master[0], order);
    for (let a = 1; a < master.length; a++) {
      next[a] = mod(master[a - 1] - xi * master[a], order);
    }
    next[master.length] = master[master.length - 1];
    master = next;
  }
  const numerators = new Array(k);
  const denominators = new Array(k);
  for (let j = 0; j < k; j++) {
    const xj = xs[j];
    // Synthetic division by (x - x_j)
    const pj = new Array(k);
    pj[k - 1] = master[k];
    for (let a = k - 1; a > 0; a--) {
      pj[a - 1] = mod(master[a] + xj * pj[a], order);
    }
    let w = 1n;
    for (let i = 0; i < k; i++) {
      if (i !== j) w = mod(w * (xj - xs[i]), order);
    }
    numerators[j] = pj;
    denominators[j] = w;
  }
  return { numerators, denominators };
}


/** @internal Same as expandBasis, expanding each numerator separately;
 * reference for expandBasis */
export function expandBasisNaive(xs: bigint[], order: bigint): {
  numerators: bigint[][],
  denominators: bigint[],
} {
  const k = xs.length;
  const numerators = new Array(k);
  const denominators = new Array(k);
  for (let j = 0; j < k; j++) {
    const xj = xs[j];
    let w = 1n;
    let pj = [1n];
    for (let i = 0; i < k; i++) {
      if (i !== j) {
        const xi = xs[i];
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
    numerators[j] = pj.map((c) => mod(c, order));
    denominators[j] = mod(w, order);
  }
  return { numerators, denominators };
}


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

    const xs = points.map(([x,]) => x);
    const ys = points.map(([, y]) => y);
    const { numerators, denominators } = expandBasis(xs, order);
    let ws: bigint[];
    try { ws = modInvBatch(denominators, order); } catch (err: unknown) {
      if (err instanceof NoInverseError) throw new InterpolationError(
        'Not all provided x\'s are distinct modulo order'
      );
      else throw err;
    }
    const coeffs = new Array(k).fill(0n);
    for (let j = 0; j < k; j++) {
      const fj = mod(ys[j] * ws[j], order);
      const pj = numerators[j];
      for (let i = 0; i < k; i++) coeffs[i] += fj * pj[i];
    }
    super(ctx, coeffs);
    this.xs = xs;
    this.ys = ys;
    this.ws = ws;
  }

  /** Evaluation at `value` in barycentric form; reference for the inherited
   * `evaluate`, which runs Horner's rule over the coefficients */
  evaluateBarycentric = (value: bigint | number): bigint => {
    const { xs, ys, ws, order } = this;
    const x = BigInt(value);
    let [b, c] = [0n, 0n];
    for (let i = 0; i < xs.length; i++) {
      if (mod(x, order) === mod(xs[i], order)) {
        return mod(ys[i], order);
      };
      const a = ws[i] * modInv(x - xs[i], order);
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

export function lagrange<P extends Point>(ctx: Group<P>) {
  return new LagrangeInterpolator(ctx);
}
