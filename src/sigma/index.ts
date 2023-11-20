import { Algorithm } from '../types';
import { Algorithms } from '../enums';
import { Group, Point } from '../backend/abstract';
import { leInt2Buff, leBuff2Int, mod } from '../utils';
import linear from './linear';
import dlog from './dlog';

import { fiatShamir, BaseSigmaProtocol, LinearRelation, SigmaProof } from './base';
import { DlogPair } from './dlog';
export { fiatShamir, BaseSigmaProtocol, LinearRelation, SigmaProof,
  DlogPair,
  linear,
  dlog,
};


export type DDHTuple<P extends Point> = {
  u: P,
  v: P,
  w: P,
}

function fillMatrix<P extends Point>(point: P, m: number, n: number): P[][] {
  return Array.from({ length: m }, (_, i) => Array.from({ length: n }, (_, i) => point));
}

export async function proveAndDlog<P extends Point>(
  ctx: Group<P>,
  witnesses: bigint[],
  pairs: DlogPair<P>[],
  opts?: { algorithm?: Algorithm, nonce?: Uint8Array },
): Promise<SigmaProof<P>> {
  const { neutral } = ctx;
  const m = pairs.length;
  const us = fillMatrix(neutral, m, m);
  for (let i = 0; i < m; i++) {
    us[i][i] = pairs[i].u;
  }
  const vs = pairs.map(({ v }) => v);
  const algorithm = opts ? (opts.algorithm || Algorithms.DEFAULT) : Algorithms.DEFAULT;
  const nonce = opts ? opts.nonce : undefined;
  return linear(ctx, algorithm).prove(witnesses, { us, vs }, nonce);
}


export async function verifyAndDlog<P extends Point>(
  ctx: Group<P>,
  pairs: DlogPair<P>[],
  proof: SigmaProof<P>,
  opts?: { nonce?: Uint8Array },
): Promise<boolean> {
  const { neutral } = ctx;
  const m = pairs.length;
  const us = fillMatrix(neutral, m, m)
  for (let i = 0; i < m; i++) {
    us[i][i] = pairs[i].u;
  }
  const vs = pairs.map(({ v }) => v);
  const nonce = opts ? (opts.nonce || undefined) : undefined;
  return linear(ctx).verify({ us, vs }, proof, nonce);
}


export async function proveEqDlog<P extends Point>(
  ctx: Group<P>,
  x: bigint,
  pairs: DlogPair<P>[],
  opts?: { algorithm?: Algorithm, nonce?: Uint8Array },
): Promise<SigmaProof<P>> {
  const { neutral } = ctx;
  const m = pairs.length;
  const witnesses = Array.from({ length: m }, (_, i) => x);
  const us = fillMatrix(neutral, m, m);
  for (let i = 0; i < m; i++) {
    us[i][i] = pairs[i].u;
  }
  const vs = pairs.map(({ v }) => v);
  const algorithm = opts ? (opts.algorithm || Algorithms.DEFAULT) : Algorithms.DEFAULT;
  const nonce = opts ? opts.nonce : undefined;
  return linear(ctx, algorithm).prove(witnesses, { us, vs }, nonce);
}

export async function verifyEqDlog<P extends Point>(
  ctx: Group<P>,
  pairs: DlogPair<P>[],
  proof: SigmaProof<P>,
  opts?: { nonce?: Uint8Array },
): Promise<boolean> {
  const { neutral } = ctx;
  const m = pairs.length;
  const us = fillMatrix(neutral, m, m);
  for (let i = 0; i < m; i++) {
    us[i][i] = pairs[i].u;
  }
  const vs = pairs.map(({ v }) => v);
  const nonce = opts ? (opts.nonce || undefined) : undefined;
  return linear(ctx).verify({ us, vs }, proof, nonce);
}


export async function proveDDH<P extends Point>(
  ctx: Group<P>,
  z: bigint,
  ddh: DDHTuple<P>,
  opts?: { algorithm?: Algorithm, nonce?: Uint8Array },
): Promise<SigmaProof<P>> {
  const { u, v, w } = ddh;
  const { generator: g } = ctx;
  return proveEqDlog(ctx, z, [{ u: g, v }, { u, v: w }], opts);
}


export async function verifyDDH<P extends Point>(
  ctx: Group<P>,
  ddh: DDHTuple<P>,
  proof: SigmaProof<P>,
  opts?: { nonce?: Uint8Array },
): Promise<boolean> {
  const { u, v, w } = ddh;
  const { generator: g } = ctx;
  return verifyEqDlog(ctx, [{ u: g, v }, { u, v: w }], proof, opts);
}


export async function proveRepresentation<P extends Point>(
  ctx: Group<P>,
  witnesses: { s: bigint, t: bigint },
  commitment: { h: P, u: P },
  opts?: { algorithm?: Algorithm, nonce?: Uint8Array },
): Promise<SigmaProof<P>> {
  const { s, t } = witnesses;
  const { h, u } = commitment;
  const { generator: g } = ctx;
  const algorithm = opts ? (opts.algorithm || Algorithms.DEFAULT) : Algorithms.DEFAULT;
  const nonce = opts ? opts.nonce : undefined;
  return linear(ctx, algorithm).prove([s, t], { us: [[g, h]], vs: [u]}, nonce);
}


export async function verifyRepresentation<P extends Point>(
  ctx: Group<P>,
  commitment: { h: P, u: P },
  proof: SigmaProof<P>,
  opts?: { nonce?: Uint8Array },
): Promise<boolean> {
  const { h, u } = commitment;
  const { generator: g } = ctx;
  const nonce = opts ? (opts.nonce || undefined) : undefined;
  return linear(ctx).verify({ us: [[g, h]], vs: [u]}, proof, nonce);
}
