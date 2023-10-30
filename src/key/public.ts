import { Group, Point } from '../backend/abstract';
import { Ciphertext } from '../elgamal/core';
import { Label } from '../types';
import { DlogProof } from '../sigma';
import { Messages } from './enums';

const backend = require('../backend');
const sigma = require('../sigma');


export type SerializedPublic = {
  value: string;
  system: Label;
}


export class PublicKey<P extends Point> {
  _ctx: Group<P>;
  _point: P;

  constructor(ctx: Group<P>, point: P) {
    this._ctx = ctx;
    this._point = point;
  }

  serialize = (): SerializedPublic => {
    return { value: this._point.toHex(), system: this._ctx.label };
  }

  public get ctx(): Group<P> {
    return this._ctx;
  }

  public get point(): P {
    return this._point;
  }

  async isEqual<Q extends Point>(other: PublicKey<Q>): Promise<boolean> {
    return (
      (await this._ctx.isEqual(other.ctx)) &&
      (await this._point.isEqual(other.point))
    );
  }

  async verifyIdentity(proof: DlogProof<P>): Promise<boolean> {
    const { _ctx: ctx, _point: pub } = this;
    const verified = await sigma.verifyDlog(ctx, ctx.generator, pub, proof);
    if (!verified) throw new Error(Messages.INVALID_IDENTITY_PROOF);
    return verified;
  }

  async encryptPoint (msgPoint: P): Promise<[Ciphertext<P>, bigint]> {
    const r = await this._ctx.randomScalar();                          // r
    const d = await this._ctx.operate(r, this._point);                // y ^ r
    const alpha = await this._ctx.combine(d, msgPoint);          // d * m
    const beta  = await this._ctx.operate(r, this._ctx.generator); // g ^ r
    return [{ alpha, beta }, r];
  }
}
