// TODO: Consider consulting https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
import { Algorithms } from '../enums';
import { Algorithm } from '../types';
import { Point, Group } from '../backend/abstract';
import { NizkProtocol } from '../nizk';
import { Signature, Signer } from './base';


export class SchnorrSignature implements Signature {
  c: Uint8Array;
  r: bigint;

  constructor(c: Uint8Array, r: bigint) {
    this.c = c;
    this.r = r;
  }
}

export class SchnorrSigner<P extends Point> extends Signer<P, SchnorrSignature> {
  protocol: NizkProtocol<P>;

  constructor(ctx: Group<P>, algorithm: Algorithm) {
    super(ctx, algorithm);
    this.protocol = new NizkProtocol(ctx, algorithm);
  }

  signBytes = async (secret: bigint, message: Uint8Array, nonce?: Uint8Array): Promise<
    SchnorrSignature
  > => {
    const { generator: g, operate } = this.ctx;
    const pub = await operate(secret, g);
    const { commitment, response } = await this.protocol.proveLinear(
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
    return this.protocol.verifyLinear(
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
