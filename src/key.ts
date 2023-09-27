import { Point } from './elgamal/abstract';
import { CryptoSystem } from './elgamal/crypto';
import {
  SerializedKey,
  SerializedPublic,
  Ciphertext,
} from './types';

const elgamal = require('./elgamal');


export class Key {
  _crypto: CryptoSystem;
  _secret: bigint;

  constructor(ctx: CryptoSystem, scalar: bigint) {
    this._crypto = ctx;
    // TODO: scalar validation according to cryptosystem
    this._secret = scalar;
  }

  public get ctx(): CryptoSystem {
    return this._crypto;
  }

  public get secret(): bigint {
    return this._secret;
  }

  public get point(): Promise<Point> {
    return this._crypto.generatePoint(this._secret);
  }

  isEqual = async (other: Key): Promise<Boolean> => {
    return (
      (await this._crypto.isEqual(other.ctx)) &&
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
    const point = await this._crypto.generatePoint(this._secret);

    return new Public(this._crypto, point);
  }

  diffieHellman = async (pub: Public): Promise<Point> => {
    await this._crypto.assertValid(pub.point);

    return this._crypto.operate(this._secret, pub.point);
  }

  decryptPoint = async (ciphertext: Ciphertext): Promise<Point> => {
    const { alpha, beta } = ciphertext;
    const d = await this._crypto.operate(this._secret, beta);  // b ^ x = (g ^ r) ^ x
    const dInv = await this._crypto.invert(d)

    return await this._crypto.combine(alpha, dInv);
  }

}


export class Public {
  _crypto: CryptoSystem;
  _point: Point;

  constructor(ctx: CryptoSystem, point: Point) {
    this._crypto = ctx;
    this._point = point;
  }

  public get ctx(): CryptoSystem {
    return this._crypto;
  }

  public get point(): Point {
    return this._point;
  }

  serialize = async (): Promise<SerializedPublic> => {
    const value = this._crypto.hexify(this._point);

    return { value };
  }

  static deserialize = async (serialized: SerializedPublic, opts: any): Promise<Public> => {
    const ctx = elgamal.initCrypto(opts.crypto);
    const { value } = serialized;

    return new Public(ctx, ctx.unhexify(value));
  }

  isEqual = async (other: Public): Promise<Boolean> => {
    return (
      (await this._crypto.isEqual(other.ctx)) &&
      (await this._point.isEqual(other.point))
    );
  }

  encryptPoint = async (msgPoint: Point): Promise<[Ciphertext, bigint]> => {
    const r = await this._crypto.randomScalar();                          // r
    const d = await this._crypto.operate(r, this._point);                // y ^ r
    const alpha = await this._crypto.combine(d, msgPoint);          // d * m
    const beta  = await this._crypto.operate(r, this._crypto.generator); // g ^ r
    return [{ alpha, beta }, r];
  }
}
