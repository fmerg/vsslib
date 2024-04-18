import { Algorithm } from '../../types';
import { Group, Point } from '../../backend/abstract';
import { SigmaProtocol, SigmaProof } from './base';
import { DlogPair } from './dlog';


export function fillMatrix<P extends Point>(point: P, m: number, n: number): P[][] {
  return Array.from({ length: m }, (_, i) => Array.from({ length: n }, (_, i) => point));
}

export class EqDlogProtocol<P extends Point> extends SigmaProtocol<P> {
  prove = async (x: bigint, pairs: DlogPair<P>[], nonce?: Uint8Array): Promise<SigmaProof<P>> => {
    const { neutral } = this.ctx;
    const m = pairs.length;
    const witnesses = Array.from({ length: m }, (_, i) => x);
    const us = fillMatrix(neutral, m, m);
    for (let i = 0; i < m; i++) {
      us[i][i] = pairs[i].u;
    }
    const vs = pairs.map(({ v }) => v);
    return this.proveLinearDlog(witnesses, { us, vs }, [], nonce);
  }
  verify = async (pairs: DlogPair<P>[], proof: SigmaProof<P>, nonce?: Uint8Array): Promise<boolean> => {
    const { neutral } = this.ctx;
    const m = pairs.length;
    const us = fillMatrix(neutral, m, m);
    for (let i = 0; i < m; i++) {
      us[i][i] = pairs[i].u;
    }
    const vs = pairs.map(({ v }) => v);
    return this.verifyLinearDlog({ us, vs }, proof, [], nonce);
  }
}

export default function<P extends Point>(ctx: Group<P>, algorithm?: Algorithm): EqDlogProtocol<P> {
  return new EqDlogProtocol(ctx, algorithm);
}
