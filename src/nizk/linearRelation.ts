import { Algorithm } from '../types';
import { Group, Point } from '../backend/abstract';
import { NizkProtocol, DlogLinear, NizkProof } from './base';


export class LinearProtocol<P extends Point> extends NizkProtocol<P> {
  prove = async (witnesses: bigint[], relation: DlogLinear<P>, nonce?: Uint8Array): Promise<NizkProof<P>> => {
    return this.proveLinearRelation(witnesses, relation, [], nonce);
  }
  verify = async (relation: DlogLinear<P>, proof: NizkProof<P>, nonce?: Uint8Array): Promise<boolean> => {
    return this.verifyLinearRelation(relation, proof, [], nonce);
  }
}

export default function<P extends Point>(ctx: Group<P>, algorithm: Algorithm): LinearProtocol<P> {
  return new LinearProtocol(ctx, algorithm);
}
