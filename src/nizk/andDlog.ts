import { Algorithm } from '../types';
import { Group, Point } from '../backend/abstract';
import { NizkProtocol, NizkProof } from './base';
import { DlogPair } from './dlog';


export function fillMatrix<P extends Point>(point: P, m: number, n: number): P[][] {
  return Array.from({ length: m }, (_, i) => Array.from({ length: n }, (_, i) => point));
}

export class AndDlogProtocol<P extends Point> extends NizkProtocol<P> {
  prove = async (witnesses: bigint[], pairs: DlogPair<P>[], nonce?: Uint8Array): Promise<NizkProof<P>> => {
    const { neutral } = this.ctx;
    const m = pairs.length;
    const us = fillMatrix(neutral, m, m);
    for (let i = 0; i < m; i++) {
      us[i][i] = pairs[i].u;
    }
    const vs = pairs.map(({ v }) => v);
    return this.proveLinearRelation(witnesses, { us, vs }, [], nonce);
  }
  verify = async (pairs: DlogPair<P>[], proof: NizkProof<P>, nonce?: Uint8Array): Promise<boolean> => {
    const { neutral } = this.ctx;
    const m = pairs.length;
    const us = fillMatrix(neutral, m, m)
    const vs = pairs.map(({ v }) => v);
    for (let i = 0; i < m; i++) {
      us[i][i] = pairs[i].u;
    }
    return this.verifyLinearRelation({ us, vs }, proof, [], nonce);
  }
}

export default function<P extends Point>(ctx: Group<P>, algorithm: Algorithm): AndDlogProtocol<P> {
  return new AndDlogProtocol(ctx, algorithm);
}
