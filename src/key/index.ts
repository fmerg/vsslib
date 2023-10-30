import { Group, Point } from '../backend/abstract';

const backend = require('../backend');


export type SerializedKey = {
  value: bigint;
}

export type SerializedPublic = {
  value: string;
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
    return { value: this._secret };
  }

  static deserialize = async (serialized: SerializedKey, opts: any): Promise<Key> => {
    const ctx = backend.initGroup(opts.crypto);

    const { value: scalar } = serialized;
    return new Key(ctx, scalar);
  }

  static generate = async (opts: any): Promise<Key> => {
    const ctx = backend.initGroup(opts.crypto);

    return new Key(ctx, await ctx.randomScalar());
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


export class Public {
  _ctx: Group<Point>;
  _point: Point;

  constructor(ctx: Group<Point>, point: Point) {
    this._ctx = ctx;
    this._point = point;
  }

  public get ctx(): Group<Point> {
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
    const ctx = backend.initGroup(opts.crypto);
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
