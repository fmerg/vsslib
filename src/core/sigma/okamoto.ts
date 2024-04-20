import { Algorithm } from '../../schemes';
import { Group, Point } from '../../backend/abstract';
import { SigmaProtocol, SigmaProof } from './base';

export class OkamotoProtocol<P extends Point> extends SigmaProtocol<P> {
  prove = async (witnesses: { s: bigint, t: bigint }, commitment: { h: P, u: P }, nonce?: Uint8Array): Promise<SigmaProof<P>> => {
    const { s, t } = witnesses;
    const { h, u } = commitment;
    const { generator: g } = this.ctx;
    return this.proveLinearDlog([s, t], { us: [[g, h]], vs: [u]}, [], nonce);
  }
  verify = async (commitment: { h: P, u: P }, proof: SigmaProof<P>, nonce?: Uint8Array): Promise<boolean> => {
    const { h, u } = commitment;
    const { generator: g } = this.ctx;
    return this.verifyLinearDlog({ us: [[g, h]], vs: [u] }, proof, [], nonce);
  }
}

export default function<P extends Point>(ctx: Group<P>, algorithm?: Algorithm): OkamotoProtocol<P> {
  return new OkamotoProtocol(ctx, algorithm);
}
