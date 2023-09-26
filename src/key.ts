import { Point } from './elgamal/abstract';
import { Cryptosystem } from './elgamal/system';
import {
  SerializedKey,
  SerializedPublic,
  Ciphertext,
} from './types';

const elgamal = require('./elgamal');


export class Key {
  _system: Cryptosystem;
  _secret: bigint;

  constructor(ctx: Cryptosystem, scalar: bigint) {
    this._system = ctx;
    // TODO: scalar validation according to cryptosystem
    this._secret = scalar;
  }

  public get ctx(): Cryptosystem {
    return this._system;
  }

  public get secret(): bigint {
    return this._secret;
  }

  public get point(): Promise<Point> {
    return this._system.generatePoint(this._secret);
  }

  isEqual = async (other: Key): Promise<Boolean> => {
    return (
      (await this._system.isEqual(other.ctx)) &&
      (this._secret == other.secret)
    );
  }

  serialize = (): SerializedKey => {
    return { value: this._secret };
  }

  static deserialize = async (serialized: SerializedKey, opts: any): Promise<Key> => {
    const ctx = elgamal.initCryptosystem(opts.system);

    const { value: scalar } = serialized;
    return new Key(ctx, scalar);
  }

  static generate = async (opts: any): Promise<Key> => {
    const ctx = elgamal.initCryptosystem(opts.system);

    return new Key(ctx, await ctx.randomScalar());
  }

  extractPublic = async (): Promise<Public> => {
    const point = await this._system.generatePoint(this._secret);

    return new Public(this._system, point);
  }

  diffieHellman = async (pub: Public): Promise<Point> => {
    await this._system.assertValid(pub.point);

    return this._system.operate(this._secret, pub.point);
  }

  decryptPoint = async (ciphertext: Ciphertext): Promise<Point> => {
    const { alpha, beta } = ciphertext;
    const d = await this._system.operate(this._secret, beta);  // b ^ x = (g ^ r) ^ x
    const dInv = await this._system.invert(d)

    return await this._system.combine(alpha, dInv);
  }

}


export class Public {
  _system: Cryptosystem;
  _point: Point;

  constructor(ctx: Cryptosystem, point: Point) {
    this._system = ctx;
    this._point = point;
  }

  public get ctx(): Cryptosystem {
    return this._system;
  }

  public get point(): Point {
    return this._point;
  }

  serialize = async (): Promise<SerializedPublic> => {
    const packed = this._system.hexify(this._point);

    return { packed };
  }

  static deserialize = async (serialized: SerializedPublic, opts: any): Promise<Public> => {
    const ctx = elgamal.initCryptosystem(opts.system);
    const { packed } = serialized;

    return new Public(ctx, ctx.unhexify(packed));
  }

  isEqual = async (other: Public): Promise<Boolean> => {
    return (
      (await this._system.isEqual(other.ctx)) &&
      (await this._point.isEqual(other.point))
    );
  }

  encryptPoint = async (msgPoint: Point): Promise<[Ciphertext, bigint]> => {
    const r = await this._system.randomScalar();                          // r
    const d = await this._system.operate(r, this._point);                // y ^ r
    const alpha = await this._system.combine(d, msgPoint);          // d * m
    const beta  = await this._system.operate(r, this._system.generator); // g ^ r
    return [{ alpha, beta }, r];
  }
}
