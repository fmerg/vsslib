import { Algorithm } from '../types';
import { Algorithms } from '../enums';
import { Group, Point } from '../backend/abstract';
import { leInt2Buff, leBuff2Int, mod } from '../utils';
import linear from './linear';
import andDlog from './andDlog';
import eqDlog from './eqDlog';
import dlog from './dlog';
import ddh from './ddh';

import { fiatShamir, BaseSigmaProtocol, LinearRelation, SigmaProof } from './base';
import { DlogPair } from './dlog';
import { DDHTuple } from './ddh';
export { fiatShamir, BaseSigmaProtocol, LinearRelation, SigmaProof,
  DlogPair,
  DDHTuple,
  linear,
  andDlog,
  eqDlog,
  dlog,
  ddh,
};


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
