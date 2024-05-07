// TODO: Consider consulting https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
import { Point, Group } from '../backend/abstract';
import { Algorithms } from '../enums';
import { Algorithm } from '../types';
import { BaseSigner } from './base';

import nizk from '../nizk';


export class SchnorrSignature {
  c: Uint8Array;
  r: bigint;

  constructor(c: Uint8Array, r: bigint) {
    this.c = c;
    this.r = r;
  }
}

export class SchnorrSigner<P extends Point> extends BaseSigner<P, SchnorrSignature> {
  constructor(ctx: Group<P>, algorithm: Algorithm) {
    super(ctx, algorithm);
  }

  signBytes = async (secret: bigint, message: Uint8Array, nonce?: Uint8Array): Promise<
    SchnorrSignature
  > => {
    const { generator: g, operate } = this.ctx;
    const pub = await operate(secret, g);
    const { commitment, response } = await nizk(this.ctx, this.algorithm).proveLinear(
      [secret],
      {
        us: [[g]],
        vs: [pub]
      },
      nonce,
      [message],
    );
    return { c: commitment[0], r: response[0] };
  }

  verifyBytes = async (
    pub: P, message: Uint8Array, signature: SchnorrSignature, nonce?: Uint8Array
  ): Promise<boolean> => {
    const { generator: g } = this.ctx;
    const { c, r } = signature;
    return nizk(this.ctx, this.algorithm).verifyLinear(
      {
        us: [[g]],
        vs: [pub]
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
