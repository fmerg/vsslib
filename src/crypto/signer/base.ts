import { Algorithm } from '../../types';
import { Point, Group } from '../../backend/abstract';

export interface Signature {
  c: Uint8Array,
  r: bigint;
}

export abstract class Signer<P extends Point, S> {
  ctx: Group<P>;
  algorithm: Algorithm;

  constructor(ctx: Group<P>, algorithm: Algorithm) {
    this.ctx = ctx;
    this.algorithm = algorithm;
  }

  abstract signBytes: (secret: bigint, message: Uint8Array, nonce?: Uint8Array) => Promise<S>;
  abstract verifyBytes: (pub: P, message: Uint8Array, signature: S, nonce?: Uint8Array) => Promise<boolean>;
}
