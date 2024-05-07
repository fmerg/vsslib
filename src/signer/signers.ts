import { Point, Group } from '../backend/abstract';
import { Algorithms } from '../enums';
import { Algorithm } from '../types';
import { NizkProtocol } from '../nizk';

export interface Signature {
  c: Uint8Array,
  r: bigint;
}


abstract class BaseSigner<P extends Point, S> {
  ctx: Group<P>;
  algorithm: Algorithm;

  constructor(ctx: Group<P>, algorithm: Algorithm) {
    this.ctx = ctx;
    this.algorithm = algorithm;
  }

  abstract signBytes: (secret: bigint, message: Uint8Array, nonce?: Uint8Array) => Promise<S>;
  abstract verifyBytes: (pub: P, message: Uint8Array, signature: S, nonce?: Uint8Array) => Promise<boolean>;
}


export class SchnorrSignature implements Signature {
  c: Uint8Array;
  r: bigint;

  constructor(c: Uint8Array, r: bigint) {
    this.c = c;
    this.r = r;
  }
}

// TODO: Consider consulting https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
export class SchnorrSigner<P extends Point> extends BaseSigner<P, SchnorrSignature> {
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
