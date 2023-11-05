import { Label } from '../types';
import { Algorithms } from '../enums';
import { Algorithm } from '../types';
import { Group, Point } from '../backend/abstract';
import { leInt2Buff, leBuff2Int, mod } from '../utils';

const utils = require('../utils');


export type LinearRelation<P extends Point> = {
  us: P[][],
  vs: P[],
}


export type DlogPair<P extends Point> = {
  u: P,
  v: P,
};


export type DDHTuple<P extends Point> = {
  u: P,
  v: P,
  w: P,
}


export type SigmaProof<P extends Point> = {
  commitments: P[],
  response: bigint[],
  algorithm: Algorithm,
}


export async function fiatShamir<P extends Point>(
  ctx: Group<P>,
  points: P[],
  scalars: bigint[],
  opts?: { algorithm?: Algorithm },
): Promise<bigint> {
  const algorithm = opts ? (opts.algorithm || Algorithms.DEFAULT) : Algorithms.DEFAULT;
  const { modBytes, ordBytes, genBytes, leBuff2Scalar } = ctx;
  const configBuff = [...modBytes, ...ordBytes, ...genBytes];
  const pointsBuff = points.reduce((acc: number[], p: P) => [...acc, ...p.toBytes()], []);
  const scalarsBuff = scalars.reduce((acc: number[], s: bigint) => [...acc, ...leInt2Buff(s)], []);
  const bytes = new Uint8Array([...configBuff, ...pointsBuff, ...scalarsBuff]);
  const digest = await utils.hash(bytes, { algorithm });
  return leBuff2Scalar(digest);
}


export async function proveLinearRelation<P extends Point>(
  ctx: Group<P>,
  xs: bigint[],
  relation: LinearRelation<P>,
  opts?: { algorithm?: Algorithm },
): Promise<SigmaProof<P>> {
  const { order, randomScalar, neutral, operate, combine } = ctx;
  const algorithm = opts ? (opts.algorithm || Algorithms.DEFAULT) : Algorithms.DEFAULT;
  const { us, vs } = relation;
  const m = vs.length;
  const n = xs.length;
  const rs = new Array(n);
  for (let j = 0; j < n; j ++) {
    rs[j] = await randomScalar();
  }
  const commitments = new Array(m);
  for (let i = 0; i < m; i++) {
    if (us[i].length !== n) throw new Error('Invalid dimensions');
    let ci = neutral;
    for (let j = 0; j < n; j++) {
      ci = await combine(ci, await operate(rs[j], us[i][j]));
    }
    commitments[i] = ci;
  }
  const c = await fiatShamir(
    ctx,
    [
      ...us.reduce((acc, ui) => [...acc, ...ui], []),
      ...vs,
      ...commitments,
    ],
    [],
    opts,
  );
  const response = new Array(n);
  for (const [j, x] of xs.entries()) {
    response[j] = mod(rs[j] + x * c, order);
  }
  return { commitments, response, algorithm };
}


export async function verifyLinearRelation<P extends Point>(
  ctx: Group<P>,
  relation: LinearRelation<P>,
  proof: SigmaProof<P>,
): Promise<boolean> {
  const { neutral, operate, combine } = ctx;
  const { us, vs } = relation;
  const { commitments, response, algorithm } = proof;
  if (vs.length !== commitments.length) throw new Error('TODO');
  const c = await fiatShamir(
    ctx,
    [
      ...us.reduce((acc, ui) => [...acc, ...ui], []),
      ...vs,
      ...commitments,
    ],
    [],
    { algorithm },
  );
  let flag = true;
  for (const [i, v] of vs.entries()) {
    const rhs = await combine(commitments[i], await operate(c, v));
    let lhs = neutral;
    for (const [j, s] of response.entries()) {
      lhs = await combine(lhs, await operate(s, us[i][j]));
    }
    flag &&= await lhs.isEqual(rhs);
  }
  return flag;
}


function fillMatrix<P extends Point>(point: P, m: number, n: number): P[][] {
  return Array.from({ length: m }, (_, i) => Array.from({ length: n }, (_, i) => point));
}

export async function proveAndDlog<P extends Point>(
  ctx: Group<P>,
  xs: bigint[],
  pairs: DlogPair<P>[],
  opts?: { algorithm?: Algorithm },
): Promise<SigmaProof<P>> {
  const { neutral } = ctx;
  const m = pairs.length;
  const us = fillMatrix(neutral, m, m);
  for (let i = 0; i < m; i++) {
    us[i][i] = pairs[i].u;
  }
  const vs = pairs.map(({ v }) => v);
  const proof = await proveLinearRelation(ctx, xs, { us, vs }, opts);
  return proof;
}


export async function verifyAndDlog<P extends Point>(
  ctx: Group<P>,
  pairs: DlogPair<P>[],
  proof: SigmaProof<P>,
): Promise<boolean> {
  const { neutral } = ctx;
  const m = pairs.length;
  const us = fillMatrix(neutral, m, m)
  for (let i = 0; i < m; i++) {
    us[i][i] = pairs[i].u;
  }
  const vs = pairs.map(({ v }) => v);
  return verifyLinearRelation(ctx, { us, vs }, proof);
}


export async function proveEqDlog<P extends Point>(
  ctx: Group<P>,
  x: bigint,
  pairs: DlogPair<P>[],
  opts?: { algorithm?: Algorithm },
): Promise<SigmaProof<P>> {
  const { neutral } = ctx;
  const m = pairs.length;
  const xs = Array.from({ length: m }, (_, i) => x);
  const us = fillMatrix(neutral, m, m);
  for (let i = 0; i < m; i++) {
    us[i][i] = pairs[i].u;
  }
  const vs = pairs.map(({ v }) => v);
  return proveLinearRelation(ctx, xs, { us, vs }, opts);
}

export async function verifyEqDlog<P extends Point>(
  ctx: Group<P>,
  pairs: DlogPair<P>[],
  proof: SigmaProof<P>,
): Promise<boolean> {
  const { neutral } = ctx;
  const m = pairs.length;
  const us = fillMatrix(neutral, m, m);
  for (let i = 0; i < m; i++) {
    us[i][i] = pairs[i].u;
  }
  const vs = pairs.map(({ v }) => v);
  return verifyLinearRelation(ctx, { us, vs }, proof);
}


export async function proveDlog<P extends Point>(
  ctx: Group<P>,
  x: bigint,
  pair: DlogPair<P>,
  opts?: { algorithm?: Algorithm },
): Promise<SigmaProof<P>> {
  const { u, v } = pair;
  return proveLinearRelation(ctx, [x], { us: [[u]], vs: [v] }, opts);
}


export async function verifyDlog<P extends Point>(
  ctx: Group<P>,
  pair: DlogPair<P>,
  proof: SigmaProof<P>,
): Promise<boolean> {
  const { u, v } = pair;
  return verifyLinearRelation(ctx, { us: [[u]], vs: [v] }, proof);
}


export async function proveDDH<P extends Point>(
  ctx: Group<P>,
  z: bigint,
  ddh: DDHTuple<P>,
  opts?: { algorithm?: Algorithm }
): Promise<SigmaProof<P>> {
  const { u, v, w } = ddh;
  return proveEqDlog(ctx, z, [{ u: ctx.generator, v }, { u, v: w }], opts);
}


export async function verifyDDH<P extends Point>(
  ctx: Group<P>,
  ddh: DDHTuple<P>,
  proof: SigmaProof<P>,
): Promise<boolean> {
  const { u, v, w } = ddh;
  return verifyEqDlog(ctx, [{ u: ctx.generator, v }, { u, v: w }], proof);
}
