import { Group, Point } from '../backend/abstract';

const backend = require('../backend');


export type SerializedPublic = {
  value: string;
}


export type Ciphertext = {
  alpha:  Point,
  beta:   Point,
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
