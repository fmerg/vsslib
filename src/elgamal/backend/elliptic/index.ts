import { ExtPointType, CurveFn as NobleCurve } from '@noble/curves/abstract/edwards';
import { ed25519 } from '@noble/curves/ed25519';
import { ed448 } from '@noble/curves/ed448';
import { jubjub } from '@noble/curves/jubjub';
import { secp256k1 } from '@noble/curves/secp256k1';
import { Label } from '../../../types';
import { Elliptic } from '../../../enums';
import { Point, Group } from '../../abstract';
import { byteLen, randomInteger } from '../../../utils';


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

  async isEqual<Q extends Point>(other: Q): Promise<boolean> {
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
    super(label, curve.CURVE.Fp.ORDER, curve.CURVE.n);
    this._base = curve.ExtendedPoint.BASE;
    this._zero = curve.ExtendedPoint.ZERO;
    this._curve = curve;
  }

  public get generator(): EcPoint {
    return new EcPoint(this._base);
  }

  public get neutral(): EcPoint {
    return new EcPoint(this._zero);
  }

  public get curve(): NobleCurve {
    return this._curve;
  }

  async isEqual<Q extends Point>(other: Group<Q>): Promise<boolean> {
    return (other instanceof EcGroup) && (this._curve == other.curve);
  }

  assertEqual = async (lhs: EcPoint, rhs: EcPoint): Promise<boolean> => {
    return await lhs.wrapped.equals(rhs.wrapped);
  }

  assertValid = async (point: EcPoint): Promise<boolean> => {
    if (await point.wrapped.equals(this._zero)) return true;
    try { point.wrapped.assertValidity(); } catch (err: any) {
      if (err.message.startsWith('bad point: ')) throw new Error('Point not on curve');
      throw err;
    }
    return true;
  }

  randomScalar = async (): Promise<bigint> => {
    // TODO: Refine
    const size = byteLen(this._order);
    return (await randomInteger(size)) % this._order;
  }

  randomPoint = async (): Promise<EcPoint> => {
    // TODO: Consider avoiding call to randomScalar
    return new EcPoint(this._base.multiply(await this.randomScalar()));
  }

  generatePoint = async (scalar: bigint): Promise<EcPoint> => {
    return new EcPoint(scalar !== __0n ? this._base.multiply(scalar) : this._zero);
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
