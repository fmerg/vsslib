import { Group, Point } from '../backend/abstract';
import { Ciphertext } from '../elgamal/core';
import { PublicKey } from './public';
import { Label } from '../types';

const backend = require('../backend');


export type SerializedKey = {
  value: bigint;
  system: Label;
}


export class PrivateKey<P extends Point> {
  _ctx: Group<P>;
  _secret: bigint;

  constructor(ctx: Group<P>, scalar: bigint) {
    this._ctx = ctx;
    this._secret = scalar;
  }

  serialize = (): SerializedKey => {
    return { value: this._secret, system: this._ctx.label };
  }

  public get ctx(): Group<P> {
    return this._ctx;
  }

  public get secret(): bigint {
    return this._secret;
  }

  public get point(): Promise<P> {
    return this._ctx.operate(this._secret, this._ctx.generator);
  }

  async isEqual<Q extends Point>(other: PrivateKey<Q>): Promise<boolean> {
    return (
      (await this._ctx.isEqual(other.ctx)) &&
      (this._secret == other.secret)
    );
  }

  async extractPublic(): Promise<PublicKey<P>> {
    const point = await this._ctx.operate(this._secret, this._ctx.generator);

    return new PublicKey(this._ctx, point);
  }

  async diffieHellman(pub: PublicKey<P>): Promise<P> {
    await this._ctx.assertValid(pub.point);

    return this._ctx.operate(this._secret, pub.point);
  }

  async decryptPoint(ciphertext: Ciphertext<P>): Promise<P> {
    const { alpha, beta } = ciphertext;
    const d = await this._ctx.operate(this._secret, beta);  // b ^ x = (g ^ r) ^ x
    const dInv = await this._ctx.invert(d)

    return await this._ctx.combine(alpha, dInv);
  }

}
