import { Group, Point } from './elgamal/abstract';
import { CryptoSystem } from './elgamal/core';
import {
  SerializedKey,
  SerializedPublic,
  Ciphertext,
} from './types';

const elgamal = require('./elgamal');


export type Ctx = CryptoSystem<Point, Group<Point>>;

export class Key {
  _ctx: Ctx;
  _secret: bigint;

  constructor(ctx: Ctx, scalar: bigint) {
    this._ctx = ctx;
    // TODO: scalar validation according to cryptosystem
    this._secret = scalar;
  }

  public get ctx(): Ctx {
    return this._ctx;
  }

  public get secret(): bigint {
    return this._secret;
  }

  public get point(): Promise<Point> {
    return this._ctx.generatePoint(this._secret);
  }

  isEqual = async (other: Key): Promise<boolean> => {
    return (
      (await this._ctx.isEqual(other.ctx)) &&
      (this._secret == other.secret)
    );
  }

  serialize = (): SerializedKey => {
    return { value: this._secret };
  }

  static deserialize = async (serialized: SerializedKey, opts: any): Promise<Key> => {
    const ctx = elgamal.initCrypto(opts.crypto);

    const { value: scalar } = serialized;
    return new Key(ctx, scalar);
  }

  static generate = async (opts: any): Promise<Key> => {
    const ctx = elgamal.initCrypto(opts.crypto);

    return new Key(ctx, await ctx.randomScalar());
  }

  extractPublic = async (): Promise<Public> => {
    const point = await this._ctx.generatePoint(this._secret);

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


export class Public {
  _ctx: Ctx;
  _point: Point;

  constructor(ctx: Ctx, point: Point) {
    this._ctx = ctx;
    this._point = point;
  }

  public get ctx(): Ctx {
    return this._ctx;
  }

  public get point(): Point {
    return this._point;
  }

  serialize = async (): Promise<SerializedPublic> => {
    const value = this._point.toHex();

    return { value };
  }

  static deserialize = async (serialized: SerializedPublic, opts: any): Promise<Public> => {
    const ctx = elgamal.initCrypto(opts.crypto);
    const { value } = serialized;

    return new Public(ctx, ctx.unhexify(value));
  }

  isEqual = async (other: Public): Promise<boolean> => {
    return (
      (await this._ctx.isEqual(other.ctx)) &&
      (await this._point.isEqual(other.point))
    );
  }

  encryptPoint = async (msgPoint: Point): Promise<[Ciphertext, bigint]> => {
    const r = await this._ctx.randomScalar();                          // r
    const d = await this._ctx.operate(r, this._point);                // y ^ r
    const alpha = await this._ctx.combine(d, msgPoint);          // d * m
    const beta  = await this._ctx.operate(r, this._ctx.generator); // g ^ r
    return [{ alpha, beta }, r];
  }
}
