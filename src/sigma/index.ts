import { Label } from '../types';
import { Algorithms } from '../enums';
import { Algorithm } from '../types';
import { Group, Point } from '../backend/abstract';
import { leInt2Buff, leBuff2Int, mod } from '../utils';

const utils = require('../utils');


export type DlogPair<P extends Point> = {
  u: P,
  v: P,
};


export type DDHTuple<P extends Point> = {
  u: P,
  v: P,
  w: P,
}


export type DlogProof<P extends Point> = {
  commitments: P[],
  response: bigint,
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


export async function proveEqDlog<P extends Point>(
  ctx: Group<P>,
  z: bigint,
  pairs: DlogPair<P>[],
  opts?: { algorithm?: Algorithm },
): Promise<DlogProof<P>> {
  const { order, randomScalar, operate } = ctx;
  const algorithm = opts ? (opts.algorithm || Algorithms.DEFAULT) : Algorithms.DEFAULT;
  const r = await randomScalar();
  const commitments = new Array(pairs.length);
  for (const [i, { u, v }] of pairs.entries()) {
    commitments[i] = await operate(r, u);
  }
  const c = await fiatShamir(
    ctx,
    [
      ...pairs.reduce((acc: P[], { u, v }: DlogPair<P>) => [...acc, u, v], []),
      ...commitments
    ],
    [],
    opts,
  );
  const response = mod(r + c * z, order);
  return { commitments, response, algorithm };
}

export async function verifyEqDlog<P extends Point>(
  ctx: Group<P>,
  pairs: DlogPair<P>[],
  proof: DlogProof<P>,
): Promise<boolean> {
  const { commitments, response, algorithm } = proof;
  if (pairs.length !== commitments.length) throw new Error('TODO');
  const { operate, combine } = ctx;
  const c = await fiatShamir(
    ctx,
    [
      ...pairs.reduce((acc: P[], { u, v }: DlogPair<P>) => [...acc, u, v], []),
      ...commitments
    ],
    [],
    { algorithm }
  );
  let flag = true;
  for (const [i, { u, v }] of pairs.entries()) {
    const lhs = await operate(response, u);
    const rhs = await combine(commitments[i], await operate(c, v));
    flag &&= await lhs.isEqual(rhs);
  }
  return flag;
}


export async function proveDlog<P extends Point>(
  ctx: Group<P>,
  z: bigint,
  u: P,
  v: P,
  opts?: { algorithm?: Algorithm },
): Promise<DlogProof<P>> {
  return proveEqDlog(ctx, z, [{ u, v }], opts);
}


export async function verifyDlog<P extends Point>(
  ctx: Group<P>,
  u: P,
  v: P,
  proof: DlogProof<P>,
): Promise<boolean> {
  return verifyEqDlog(ctx, [{ u, v }], proof);
}


export async function proveDDH<P extends Point>(
  ctx: Group<P>,
  z: bigint,
  ddh: DDHTuple<P>,
  opts?: { algorithm?: Algorithm }
): Promise<DlogProof<P>> {
  const { u, v, w } = ddh;
  return proveEqDlog(ctx, z, [{ u: ctx.generator, v }, { u, v: w }], opts);
}


export async function verifyDDH<P extends Point>(
  ctx: Group<P>,
  ddh: DDHTuple<P>,
  proof: DlogProof<P>,
): Promise<boolean> {
  const { u, v, w } = ddh;
  return verifyEqDlog(ctx, [{ u: ctx.generator, v }, { u, v: w }], proof);
}
