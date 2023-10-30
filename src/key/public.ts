import { Group, Point } from '../backend/abstract';
import { Ciphertext } from '../elgamal/core';
import { Label } from '../types';

const backend = require('../backend');


export type SerializedPublic = {
  value: string;
  system: Label;
}


export class Public<P extends Point> {
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

  async isEqual<Q extends Point>(other: Public<Q>): Promise<boolean> {
    return (
      (await this._ctx.isEqual(other.ctx)) &&
      (await this._point.isEqual(other.point))
    );
  }

  async encryptPoint (msgPoint: P): Promise<[Ciphertext<P>, bigint]> {
    const r = await this._ctx.randomScalar();                          // r
    const d = await this._ctx.operate(r, this._point);                // y ^ r
    const alpha = await this._ctx.combine(d, msgPoint);          // d * m
    const beta  = await this._ctx.operate(r, this._ctx.generator); // g ^ r
    return [{ alpha, beta }, r];
  }
}
