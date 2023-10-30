import { Group, Point } from '../backend/abstract';
import { Public } from './public';
import { Label } from '../types';

const backend = require('../backend');


export type SerializedKey = {
  value: bigint;
  system: Label;
}

export type Ciphertext = {
  alpha:  Point,
  beta:   Point,
}


export class Key {
  _ctx: Group<Point>;
  _secret: bigint;

  constructor(ctx: Group<Point>, scalar: bigint) {
    this._ctx = ctx;
    // TODO: scalar validation according to cryptosystem
    this._secret = scalar;
  }

  public get ctx(): Group<Point> {
    return this._ctx;
  }

  public get secret(): bigint {
    return this._secret;
  }

  public get point(): Promise<Point> {
    return this._ctx.operate(this._secret, this._ctx.generator);
  }

  isEqual = async (other: Key): Promise<boolean> => {
    return (
      (await this._ctx.isEqual(other.ctx)) &&
      (this._secret == other.secret)
    );
  }

  serialize = (): SerializedKey => {
    return { value: this._secret, system: this._ctx.label };
  }

  extractPublic = async (): Promise<Public> => {
    const point = await this._ctx.operate(this._secret, this._ctx.generator);

    return new Public(this._ctx, point);
  }

  diffieHellman = async (pub: Public): Promise<Point> => {
    await this._ctx.assertValid(pub.point);

    return this._ctx.operate(this._secret, pub.point);
  }

  decryptPoint = async (ciphertext: Ciphertext): Promise<Point> => {
    const { alpha, beta } = ciphertext;
    const d = await this._ctx.operate(this._secret, beta);  // b ^ x = (g ^ r) ^ x
    const dInv = await this._ctx.invert(d)

    return await this._ctx.combine(alpha, dInv);
  }

}
