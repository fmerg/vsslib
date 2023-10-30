import { Group, Point } from '../backend/abstract';
import { Ciphertext } from '../elgamal/core';
import { Label } from '../types';
import { DlogProof } from '../sigma';
import { Messages } from './enums';

const backend = require('../backend');
const sigma = require('../sigma');


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
    const { ctx: ctx, point: pub } = this;
    const verified = await sigma.verifyDlog(ctx, ctx.generator, pub, proof);
    if (!verified) throw new Error(Messages.INVALID_IDENTITY_PROOF);
    return verified;
  }

  async encryptPoint (msgPoint: P): Promise<[Ciphertext<P>, bigint]> {
    const { ctx, point } = this;
    const r = await ctx.randomScalar();                          // r
    const d = await ctx.operate(r, point);                // y ^ r
    const alpha = await ctx.combine(d, msgPoint);          // d * m
    const beta  = await ctx.operate(r, ctx.generator); // g ^ r
    return [{ alpha, beta }, r];
  }
}
