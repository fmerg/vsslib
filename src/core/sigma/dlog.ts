import { Algorithm } from '../../types';
import { Group, Point } from '../../backend/abstract';
import { SigmaProtocol, SigmaProof } from './base';

export type DlogPair<P extends Point> = {
  u: P,
  v: P,
};

export class DlogProtocol<P extends Point> extends SigmaProtocol<P> {
  prove = async (x: bigint, { u, v }: DlogPair<P>, nonce?: Uint8Array): Promise<SigmaProof<P>> => {
    return this.proveLinearDlog([x], { us: [[u]], vs: [v] }, [], nonce);
  }
  verify = async ({ u, v }: DlogPair<P>, proof: SigmaProof<P>, nonce?: Uint8Array): Promise<boolean> => {
    return this.verifyLinearDlog({ us: [[u]], vs: [v] }, proof, [], nonce);
  }
}

export default function<P extends Point>(ctx: Group<P>, algorithm?: Algorithm): DlogProtocol<P> {
  return new DlogProtocol(ctx, algorithm);
}
