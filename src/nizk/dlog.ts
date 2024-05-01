import { Algorithm } from '../types';
import { Group, Point } from '../backend/abstract';
import { NizkProtocol, NizkProof } from './base';

export type DlogPair<P extends Point> = {
  u: P,
  v: P,
};

export class DlogProtocol<P extends Point> extends NizkProtocol<P> {
  prove = async (x: bigint, { u, v }: DlogPair<P>, nonce?: Uint8Array): Promise<NizkProof<P>> => {
    return this.proveLinearRelation([x], { us: [[u]], vs: [v] }, [], nonce);
  }
  verify = async ({ u, v }: DlogPair<P>, proof: NizkProof<P>, nonce?: Uint8Array): Promise<boolean> => {
    return this.verifyLinearRelation({ us: [[u]], vs: [v] }, proof, [], nonce);
  }
}

export default function<P extends Point>(ctx: Group<P>, algorithm: Algorithm): DlogProtocol<P> {
  return new DlogProtocol(ctx, algorithm);
}
