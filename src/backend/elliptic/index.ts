import { ExtPointType, CurveFn as NobleCurve } from '@noble/curves/abstract/edwards';
import { ed25519 } from '@noble/curves/ed25519';
import { ed448 } from '@noble/curves/ed448';
import { jubjub } from '@noble/curves/jubjub';
import { secp256k1 } from '@noble/curves/secp256k1';
import { Label } from '../../types';
import { Elliptic } from '../../enums';
import { Messages } from '../enums';
import { Point, Group } from '../abstract';
import { mod, leBuff2Int } from '../../utils';


const __0n = BigInt(0);


interface NoblePoint extends ExtPointType {
  toRawBytes?: Function;
  toHex?: Function;
};


class EcPoint implements Point {
  _wrapped: NoblePoint;

  constructor(wrapped: NoblePoint) {
    this._wrapped = wrapped;
  }

  public get wrapped(): NoblePoint {
    return this._wrapped;
  }

  async equals<Q extends Point>(other: Q): Promise<boolean> {
    return (other instanceof EcPoint) && (this._wrapped.equals(other.wrapped));
  }

  toBytes = (): Uint8Array => {
    return this._wrapped.toRawBytes!();
  }

  toHex = (): string => {
    return this._wrapped.toHex!();
  }
}


export class EcGroup extends Group<EcPoint> {
  _base: NoblePoint;
  _zero: NoblePoint;
  _curve: NobleCurve;

  constructor(label: Label, curve: NobleCurve) {
    const modulus = curve.CURVE.Fp.ORDER;
    const order = curve.CURVE.n;
    const base = curve.ExtendedPoint.BASE;
    const zero = curve.ExtendedPoint.ZERO;
    const generator = new EcPoint(base);
    const neutral = new EcPoint(zero);
    super(label, modulus, order, generator, neutral);
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

  randomBytes = async (): Promise<Uint8Array> => {
    const { randomBytes, Fp } = this.curve.CURVE;
    return randomBytes(Fp.BYTES);
  }

  randomScalar = async (): Promise<bigint> => {
    const { randomBytes, Fp } = this.curve.CURVE;
    return mod(leBuff2Int(randomBytes(Fp.BYTES)), this.order);
  }

  randomPoint = async (): Promise<EcPoint> => {
    const { randomBytes, Fp } = this.curve.CURVE;
    const scalar = mod(leBuff2Int(randomBytes(Fp.BYTES)), this.order);
    return new EcPoint(this._base.multiply(scalar));
  }

  validateBytes = async (bytes: Uint8Array, opts?: { raiseOnInvalid: boolean }): Promise<boolean> => {
    const flag = bytes.length <= this.curve.CURVE.Fp.BYTES;
    if (!flag && (opts ? opts.raiseOnInvalid : true))
      throw new Error(Messages.INVALID_BYTELENGTH);
    return flag;
  }

  validateScalar = async (scalar: bigint, opts?: { raiseOnInvalid: boolean }): Promise<boolean> => {
    const flag = 0 < scalar && scalar < this.order;
    if (!flag && (opts ? opts.raiseOnInvalid : true))
      throw new Error(Messages.INVALID_SCALAR)
    return flag;
  }

  validatePoint = async (point: EcPoint, opts?: { raiseOnInvalid: boolean}): Promise<boolean> => {
    let flag = true;
    if (await point.wrapped.equals(this._zero)) return flag;
    try { point.wrapped.assertValidity(); } catch (err: any) {
      if (err.message.startsWith('bad point: ')) {
        flag = false;
        if (opts ? opts.raiseOnInvalid : true)
          throw new Error(Messages.POINT_NOT_IN_SUBGROUP);
      }
      else throw err;
    }
    return flag;
  }

  operate = async (scalar: bigint, point: EcPoint): Promise<EcPoint> => {
    return new EcPoint(scalar !== __0n ? point.wrapped.multiply(scalar) : this._zero);
  }

  combine = async (lhs: EcPoint, rhs: EcPoint): Promise<EcPoint> => {
    return new EcPoint(lhs.wrapped.add(rhs.wrapped));
  }

  invert = async (point: EcPoint): Promise<EcPoint> => {
    return new EcPoint(point.wrapped.negate());
  }

  unpack = (bytes: Uint8Array): EcPoint => {
    return new EcPoint(this._curve.ExtendedPoint.fromHex(bytes));
  }

  unhexify = (hexnum: string): EcPoint => {
    return new EcPoint(this._curve.ExtendedPoint.fromHex(hexnum));
  }

  generateKeypair = async (secret?: bigint): Promise<{ secret: bigint, pub: EcPoint }> => {
    const { randomScalar, operate, generator } = this;
    secret = secret || await randomScalar();
    const pub = await operate(secret, generator);
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

export default function(label: Label): EcGroup {
  let group: EcGroup;

  switch (label) {
    case Elliptic.ED25519:
    case Elliptic.ED448:
    case Elliptic.JUBJUB:
      group = new EcGroup(label, __curves[label]);
      break;
    default:
      throw new Error(
        `Unsupported crypto: ${label}`
    );
  }

  return group;
}
