import { Algorithm } from '../types';
import { Group, Point } from '../backend/abstract';
import { NizkProtocol, NizkProof } from './base';

export type DDHTuple<P extends Point> = {
  u: P,
  v: P,
  w: P,
}

export class DDHProtocol<P extends Point> extends NizkProtocol<P> {
  prove = async (z: bigint, { u, v, w }: DDHTuple<P>, nonce?: Uint8Array): Promise<NizkProof<P>> => {
    const { generator: g, neutral: n } = this.ctx;
    return this.proveLinearRelation([z, z], { us: [[g, n], [n, u]], vs: [v, w] }, [], nonce);
  }
  verify = async ({ u, v, w }: DDHTuple<P>, proof: NizkProof<P>, nonce?: Uint8Array): Promise<boolean> => {
    const { generator: g, neutral: n } = this.ctx;
    return this.verifyLinearRelation({ us: [[g, n], [n, u]], vs: [v, w] }, proof, [], nonce);
  }
}

export default function<P extends Point>(ctx: Group<P>, algorithm: Algorithm): DDHProtocol<P> {
  return new DDHProtocol(ctx, algorithm);
}
