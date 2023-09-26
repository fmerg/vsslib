import { ed25519 } from '@noble/curves/ed25519';
import { ed448 } from '@noble/curves/ed448';
import { jubjub } from '@noble/curves/jubjub';
import { secp256k1 } from '@noble/curves/secp256k1';

import { Label } from '../../../types';
import { Group, Point } from '../../abstract';
import { Elliptic } from '../../../enums';


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


// Models the point structure provided by @noble/curves
type NoblePoint = {
  equals: Function
  multiply: Function
  add: Function
  negate: Function
  assertValidity: Function
  toRawBytes: Function
  toHex: Function
}


// Models the curve structure provided by @noble/curves
type NobleCurve = {
  CURVE: {
    n: bigint,
    Fp: {
      ORDER: bigint
    }
  },
  ExtendedPoint: {
    BASE: NoblePoint,
    ZERO: NoblePoint,
    fromHex: Function,
  },
}


class EcGroup extends Group {
  _curve: NobleCurve;
  _base:  NoblePoint;
  _zero:  NoblePoint;

  constructor(label: Label, curve: any) {
    super(label, curve.CURVE.Fp.ORDER, curve.CURVE.n);

    this._curve = curve;
    this._base  = curve.ExtendedPoint.BASE;
    this._zero  = curve.ExtendedPoint.ZERO;
  }

  public get curve(): NobleCurve {
    return this._curve;
  }

  public get generator(): Point {
    return new EcPoint(this, this._base);
  }

  public get neutral(): Point {
    return new EcPoint(this, this._zero);
  }

  isEqual = async (other: Group): Promise<Boolean> => {
    return (
      (other instanceof EcGroup) && (this._curve == other.curve)
    );
  }

  operate = async (s: bigint, p: Point): Promise<Point> => {
    return new EcPoint(
      this,
      s != BigInt(0) ?
        (p as EcPoint).wrapped.multiply(s) :
        this._zero
    );
  }

  combine = async (p: Point, q: Point): Promise<Point> => {
    return new EcPoint(this, (p as EcPoint).wrapped.add((q as EcPoint).wrapped));
  }

  invert = async (p: Point): Promise<Point> => {
    return new EcPoint(this, (p as EcPoint).wrapped.negate());
  }

  randomPoint = async (): Promise<Point> => {
    const r = await this.randomScalar();;
    return new EcPoint(this, this._base.multiply(r));
  }

  generatePoint = async (s: bigint): Promise<Point> => {
    return new EcPoint(this, s != BigInt(0) ? this._base.multiply(s) : this._zero);
  }

  assertValid = async (p: Point): Promise<Boolean> => {
    if (!(p instanceof EcPoint)) {
      throw new Error('Point not of type `EcPoint`');
    }

    if (!(await p.group.isEqual(this))) {
      throw new Error('Point not in group');
    }

    if (await p.isEqual(this.neutral)) return true;

    try {
      p.wrapped.assertValidity();
    } catch {
      throw new Error('Point not on curve');
    }

    return true;
  }

  assertEqual = async (p: Point, q: Point): Promise<Boolean> => {
    if (!(p instanceof EcPoint)) {
      throw new Error('Point not of type `EcPoint`');
    }
    if (!(q instanceof EcPoint)) {
      throw new Error('Point not of type `EcPoint`');
    }

    return (
      await p.group.isEqual(this) &&
      await q.group.isEqual(this) &&
      await p.wrapped.equals(q.wrapped)
    );
  }

  pack = (p: Point): Uint8Array => {
    return (p as EcPoint).wrapped.toRawBytes();
  }

  unpack = (pBytes: Uint8Array): Point => {
    return new EcPoint(this, this._curve.ExtendedPoint.fromHex(pBytes));
  }

  hexify = (p: Point): string => {
    return (p as EcPoint).wrapped.toHex();
  }

  unhexify = (pHex: string): Point => {
    return new EcPoint(this, this._curve.ExtendedPoint.fromHex(pHex));
  }
}


class EcPoint extends Point {
  _wrapped: NoblePoint;

  constructor(group: EcGroup, wrapped: NoblePoint) {
    super(group);
    this._wrapped = wrapped;
  }

  public get wrapped(): NoblePoint {
    return this._wrapped;
  }
}


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
        `Unsupported system: ${label}`
    );
  }

  return group;
}
