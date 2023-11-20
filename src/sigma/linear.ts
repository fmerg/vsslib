import { Algorithm } from '../types';
import { Group, Point } from '../backend/abstract';
import { BaseSigmaProtocol, LinearRelation, SigmaProof } from './base';


export class LinearProtocol<P extends Point> extends BaseSigmaProtocol<P> {
  prove = async (witnesses: bigint[], relation: LinearRelation<P>, nonce?: Uint8Array): Promise<SigmaProof<P>> => {
    return this.proveLinear(witnesses, relation, nonce);
  }
  verify = async (relation: LinearRelation<P>, proof: SigmaProof<P>, nonce?: Uint8Array): Promise<boolean> => {
    return this.verifyLinear(relation, proof, nonce);
  }
}

export default function<P extends Point>(ctx: Group<P>, algorithm?: Algorithm): LinearProtocol<P> {
  return new LinearProtocol(ctx, algorithm);
}
