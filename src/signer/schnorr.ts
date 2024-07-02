// TODO: Consider consulting https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
import { Point, Group } from '../backend';
import { Algorithms } from '../enums';
import { Algorithm } from '../types';
import { BaseSigner } from './base';

import nizk from '../nizk';


export type SchnorrSignature = { c: Uint8Array, r: Uint8Array };

export class SchnorrSigner<P extends Point> extends BaseSigner<P, SchnorrSignature> {
  constructor(ctx: Group<P>, algorithm: Algorithm) {
    super(ctx, algorithm);
  }

  signBytes = async (secret: Uint8Array, message: Uint8Array, nonce?: Uint8Array): Promise<
    SchnorrSignature
  > => {
    const { generator: g, exp } = this.ctx;
    const x = await this.ctx.leBuff2Scalar(secret);
    const y = await exp(g, x);
    const { commitment, response } = await nizk(this.ctx, this.algorithm).proveLinear(
      [x],
      {
        us: [[g]],
        vs: [y]
      },
      nonce,
      [message],
    );
    return { c: commitment[0], r: response[0] };
  }

  verifyBytes = async (
    publicBytes: Uint8Array, message: Uint8Array, signature: SchnorrSignature, nonce?: Uint8Array
  ): Promise<boolean> => {
    const { generator: g } = this.ctx;
    const { c, r } = signature;
    const y = await this.ctx.unpackValid(publicBytes);
    return nizk(this.ctx, this.algorithm).verifyLinear(
      {
        us: [[g]],
        vs: [y]
      },
      {
        commitment: [c],
        response: [r],
      },
      nonce,
      [message],
    );
  }
}


export default function<P extends Point>(ctx: Group<P>, algorithm: Algorithm) {
  return new SchnorrSigner(ctx, algorithm);
}
