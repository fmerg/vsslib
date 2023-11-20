import { Algorithm } from '../types';
import { Algorithms } from '../enums';
import { Group, Point } from '../backend/abstract';
import { leInt2Buff, leBuff2Int, mod } from '../utils';
const utils = require('../utils');

export async function fiatShamir<P extends Point>(
  ctx: Group<P>,
  points: P[],
  scalars: bigint[],
  opts?: { algorithm?: Algorithm, nonce?: Uint8Array },
): Promise<bigint> {
  const algorithm = opts ? (opts.algorithm || Algorithms.DEFAULT) : Algorithms.DEFAULT;
  const nonce = opts ? (opts.nonce || Uint8Array.from([])) : Uint8Array.from([]);
  const { modBytes, ordBytes, genBytes, leBuff2Scalar } = ctx;
  const configBuff = [...modBytes, ...ordBytes, ...genBytes];
  const pointsBuff = points.reduce((acc: number[], p: P) => [...acc, ...p.toBytes()], []);
  const scalarsBuff = scalars.reduce((acc: number[], s: bigint) => [...acc, ...leInt2Buff(s)], []);
  const bytes = Uint8Array.from([...configBuff, ...pointsBuff, ...scalarsBuff, ...nonce]);
  const digest = await utils.hash(bytes, { algorithm });
  return leBuff2Scalar(digest);
}

export type LinearRelation<P extends Point> = {
  us: P[][],
  vs: P[],
}

export type SigmaProof<P extends Point> = {
  commitments: P[],
  response: bigint[],
  algorithm: Algorithm,
}

export abstract class BaseSigmaProtocol<P extends Point> {
  ctx: Group<P>;
  algorithm: Algorithm;

  constructor(ctx: Group<P>, algorithm?: Algorithm) {
    this.ctx = ctx;
    this.algorithm = algorithm || Algorithms.DEFAULT;
  }

  abstract prove: (witnesses: any, relation: any, nonce?: Uint8Array) => Promise<SigmaProof<P>>;
  abstract verify: (relation: any, proof: SigmaProof<P>, nonce?: Uint8Array) => Promise<boolean>;

  async proveLinear(witnesses: bigint[], relation: LinearRelation<P>, nonce?: Uint8Array): Promise<SigmaProof<P>> {
    const { ctx: { order, randomScalar, neutral, operate, combine }, algorithm } = this;
    const { us, vs } = relation;
    const m = vs.length;
    const n = witnesses.length;
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
    nonce = nonce || Uint8Array.from([]);
    const c = await fiatShamir(
      this.ctx,
      [
        ...us.reduce((acc, ui) => [...acc, ...ui], []),
        ...vs,
        ...commitments,
      ],
      [],
      { nonce, algorithm }
    );
    const response = new Array(n);
    for (const [j, x] of witnesses.entries()) {
      response[j] = mod(rs[j] + x * c, order);
    }
    return { commitments, response, algorithm };
  }


  async verifyLinear(relation: LinearRelation<P>, proof: SigmaProof<P>, nonce?: Uint8Array): Promise<boolean> {
    const { neutral, operate, combine } = this.ctx;
    const { us, vs } = relation;
    const { commitments, response, algorithm } = proof;
    if (vs.length !== commitments.length) throw new Error('Invalid dimensions');
    nonce = nonce || Uint8Array.from([]);
    const c = await fiatShamir(
      this.ctx,
      [
        ...us.reduce((acc, ui) => [...acc, ...ui], []),
        ...vs,
        ...commitments,
      ],
      [],
      { algorithm, nonce },
    );
    let flag = true;
    for (const [i, v] of vs.entries()) {
      if (us[i].length !== response.length) throw new Error('Invalid dimensions');
      const rhs = await combine(commitments[i], await operate(c, v));
      let lhs = neutral;
      for (const [j, s] of response.entries()) {
        lhs = await combine(lhs, await operate(s, us[i][j]));
      }
      flag &&= await lhs.equals(rhs);
    }
    return flag;
  }
}
