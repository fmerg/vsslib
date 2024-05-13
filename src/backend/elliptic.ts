import { ExtPointType, CurveFn as NobleCurve } from '@noble/curves/abstract/edwards';
import { ed25519 } from '@noble/curves/ed25519';
import { ed448 } from '@noble/curves/ed448';
import { jubjub } from '@noble/curves/jubjub';
import { secp256k1 } from '@noble/curves/secp256k1';
import { Elliptic } from '../enums';
import { System } from '../types';
import { ErrorMessages } from '../errors';
import { Point, Group } from './abstract';
import { mod, leBuff2Int } from '../arith';


const __0n = BigInt(0);


interface NoblePoint extends ExtPointType {
  toRawBytes?: Function;
};


class EcPoint implements Point {
  _wrapped: NoblePoint;

  constructor(wrapped: NoblePoint) {
    this._wrapped = wrapped;
  }

  toBytes = (): Uint8Array => this._wrapped.toRawBytes!();

  public get wrapped(): NoblePoint {
    return this._wrapped;
  }

  async equals<Q extends Point>(other: Q): Promise<boolean> {
    return (other instanceof EcPoint) && (this._wrapped.equals(other.wrapped));
  }

}


export class EcGroup extends Group<EcPoint> {
  _base: NoblePoint;
  _zero: NoblePoint;
  _curve: NobleCurve;

  constructor(system: System, curve: NobleCurve) {
    const modulus = curve.CURVE.Fp.ORDER;
    const order = curve.CURVE.n;
    const base = curve.ExtendedPoint.BASE;
    const zero = curve.ExtendedPoint.ZERO;
    const generator = new EcPoint(base);
    const neutral = new EcPoint(zero);
    super(system, modulus, order, generator, neutral);
    this._base = base;
    this._zero = zero;
    this._curve = curve;
  }

  public get curve(): NobleCurve {
    return this._curve;
  }

  async equals<Q extends Point>(other: Group<Q>): Promise<boolean> {
    return (other instanceof EcGroup) && (this._curve == other.curve);
  }

  randomScalarBuff = async (): Promise<Uint8Array> =>
    this.curve.CURVE.randomBytes(this.curve.CURVE.Fp.BYTES);

  randomScalar = async (): Promise<bigint> => mod(
    leBuff2Int(this.curve.CURVE.randomBytes(this.curve.CURVE.Fp.BYTES)),
    this.order
  );

  randomPoint = async (): Promise<EcPoint> => new EcPoint(
    this._base.multiply(mod(
      leBuff2Int(this.curve.CURVE.randomBytes(this.curve.CURVE.Fp.BYTES)),
      this.order
    ))
  );

  validateScalar = async (scalar: bigint, opts?: { raiseOnInvalid: boolean }): Promise<boolean> => {
    const flag = 0 < scalar && scalar < this.order;
    if (!flag && (opts ? opts.raiseOnInvalid : true))
      throw new Error(ErrorMessages.INVALID_SCALAR)
    return flag;
  }

  validatePoint = async (point: EcPoint, opts?: { raiseOnInvalid: boolean}): Promise<boolean> => {
    let flag = true;
    if (await point.wrapped.equals(this._zero)) return flag;
    try { point.wrapped.assertValidity(); } catch (err: any) {
      if (err.message.startsWith('bad point: ')) {
        flag = false;
        if (opts ? opts.raiseOnInvalid : true)
          throw new Error(ErrorMessages.INVALID_POINT);
      }
      else throw err;
    }
    return flag;
  }

  exp = async (scalar: bigint, point: EcPoint): Promise<EcPoint> => new EcPoint(
    scalar !== __0n ? point.wrapped.multiply(scalar) : this._zero
  );

  operate = async (lhs: EcPoint, rhs: EcPoint): Promise<EcPoint> => new EcPoint(
    lhs.wrapped.add(rhs.wrapped)
  );

  invert = async (point: EcPoint): Promise<EcPoint> => new EcPoint(
    point.wrapped.negate()
  );

  unpack = (bytes: Uint8Array): EcPoint => {
    let unpacked;
    try {
      unpacked = new EcPoint(this._curve.ExtendedPoint.fromHex(bytes));
    } catch (err: any) {
      throw new Error(`bad encoding: ${err.message}`)
    }
    return unpacked;
  }

  unpackValid = async (bytes: Uint8Array): Promise<EcPoint> => {
    const unpacked = this.unpack(bytes);
    await this.validatePoint(unpacked);
    return unpacked;
  }

  generateSecret = async (secret?: bigint): Promise<{ secret: bigint, pub: EcPoint }> => {
    secret = secret || await this.randomScalar();
    const pub = await this.exp(secret, this.generator);
    return { secret, pub };
  }
}


const __curves = {
  [Elliptic.ED25519]: ed25519,
  [Elliptic.ED448]: ed448,
  [Elliptic.JUBJUB]: jubjub,
  // 'secp256k1': secp256k1,
  // 'pallas': pallas,
  // 'vesta': vesta,
  // 'p256': p256,
  // 'p384': p384,
  // 'p521': p521,
  // 'bn254': bn254,
};

export function initElliptic(system: System): EcGroup {
  let group: EcGroup;

  switch (system) {
    case Elliptic.ED25519:
    case Elliptic.ED448:
    case Elliptic.JUBJUB:
      group = new EcGroup(system, __curves[system]);
      break;
    default:
      throw new Error(
        `Unsupported group: ${system}`
      )
  }

  return group;
}
