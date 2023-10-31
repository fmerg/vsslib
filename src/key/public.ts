import { Group, Point } from '../backend/abstract';
import { Ciphertext } from '../elgamal/core';
import { Label } from '../types';
import { DlogProof } from '../sigma';
import { Messages } from './enums';

const backend = require('../backend');
const sigma = require('../sigma');
const elgamal = require('../elgamal');


export type SerializedPublicKey = {
  value: string;
  system: Label;
}


export class PublicKey<P extends Point> {
  ctx: Group<P>;
  point: P;

  constructor(ctx: Group<P>, point: P) {
    this.ctx = ctx;
    this.point = point;
  }

  serialize = (): SerializedPublicKey => {
    const { ctx, point } = this;
    return { value: point.toHex(), system: ctx.label };
  }

  async isEqual<Q extends Point>(other: PublicKey<Q>): Promise<boolean> {
    return (
      (await this.ctx.isEqual(other.ctx)) &&
      (await this.point.isEqual(other.point))
    );
  }

  async verifyIdentity(proof: DlogProof<P>): Promise<boolean> {
    const { ctx, point: pub } = this;
    const verified = await sigma.verifyDlog(ctx, ctx.generator, pub, proof);
    if (!verified) throw new Error(Messages.INVALID_IDENTITY_PROOF);
    return verified;
  }

  async encrypt(message: P): Promise<{
    ciphertext: Ciphertext<P>, randomness: bigint, decryptor: P
  }> {
    return elgamal.encrypt(this.ctx, message, this.point);
  }

  async proveEncryption(
    ciphertext: Ciphertext<P>,
    randomness: bigint,
    opts?: { algorithm?: Algorithm }
  ): Promise<DlogProof<P>> {
    return elgamal.proveEncryption(this.ctx, ciphertext, randomness, opts);
  }
}
