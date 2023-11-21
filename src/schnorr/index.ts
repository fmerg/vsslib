import { Algorithm } from '../types';
import { Algorithms } from '../enums';
import { Point, Group } from '../backend/abstract';
import { DlogProtocol } from '../sigma/dlog';
import { SigmaProof } from '../sigma/base';


export type SchnorrSignature<P extends Point> = SigmaProof<P>;


export class SchnorrSigner<P extends Point> extends DlogProtocol<P> {

  signBytes = async (secret: bigint, message: Uint8Array, nonce?: Uint8Array): Promise<SchnorrSignature<P>> => {
    const { generator: g, operate } = this.ctx;
    const pub = await operate(secret, g);
    return this.proveLinearDlog([secret], { us: [[g]], vs: [pub] }, [message], nonce);
  }

  verifyBytes = async (pub: P, message: Uint8Array, signature: SchnorrSignature<P>, nonce?: Uint8Array): Promise<boolean> => {
    const { generator: g } = this.ctx;
    return this.verifyLinearDlog({ us: [[g]], vs: [pub] }, signature, [message], nonce);
  }
}

export default function<P extends Point>(ctx: Group<P>, algorithm?: Algorithm): SchnorrSigner<P> {
  return new SchnorrSigner(ctx, algorithm);
}

