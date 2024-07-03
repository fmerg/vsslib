import { ExtPointType, CurveFn as _Curve } from '@noble/curves/abstract/edwards';
import { ed25519 } from '@noble/curves/ed25519';
import { ed448 } from '@noble/curves/ed448';
import { jubjub } from '@noble/curves/jubjub';

import { Point, Group } from './abstract';
import { Elliptic } from 'vsslib/enums';
import { System } from 'vsslib/types';
import { BadPointError, BadScalarError } from 'vsslib/errors';
import { mod, leBuff2Int } from 'vsslib/arith';


const __0n = BigInt(0);

interface _CurvePoint extends ExtPointType { toRawBytes?: Function; };


class EcPoint implements Point {
  wrapped: _CurvePoint;
  toBytes = (): Uint8Array => this.wrapped.toRawBytes!();

  constructor(wrapped: _CurvePoint) {
    this.wrapped = wrapped;
  }

  async equals<Q extends Point>(other: Q): Promise<boolean> {
    return (other instanceof EcPoint) && (this.wrapped.equals(other.wrapped));
  }
}


export class EcGroup extends Group<EcPoint> {
  _base: _CurvePoint;
  _zero: _CurvePoint;
  curve: _Curve;

  constructor(system: System, curve: _Curve) {
    const modulus = curve.CURVE.Fp.ORDER;
    const order = curve.CURVE.n;
    const base = curve.ExtendedPoint.BASE;
    const zero = curve.ExtendedPoint.ZERO;
    const generator = new EcPoint(base);
    const neutral = new EcPoint(zero);
    super(system, modulus, order, generator, neutral);
    this._base = base;
    this._zero = zero;
    this.curve = curve;
  }

  randomScalar = async (): Promise<bigint> => mod(
    leBuff2Int(this.curve.CURVE.randomBytes(this.curve.CURVE.Fp.BYTES)),
    this.order
  );

  randomSecret = async (): Promise<Uint8Array> =>
    this.curve.CURVE.randomBytes(this.curve.CURVE.Fp.BYTES);

  randomPoint = async (): Promise<EcPoint> => new EcPoint(
    this._base.multiply(mod(
      leBuff2Int(this.curve.CURVE.randomBytes(this.curve.CURVE.Fp.BYTES)),
      this.order
    ))
  );

  randomPublic = async (): Promise<Uint8Array> => (
    await this.randomPoint()).toBytes();

  validateScalar = async (scalar: bigint): Promise<boolean> => {
    const flag = 0 < scalar && scalar < this.order;
    if (!flag) throw new BadScalarError(
      `Scalar not in range`
    );
    return flag;
  }

  validatePoint = async (point: EcPoint): Promise<boolean> => {
    let flag = true;
    if (await point.wrapped.equals(this._zero)) return flag;
    try { point.wrapped.assertValidity(); } catch (err: any) {
      if (err.message.startsWith('bad point: ')) throw new BadPointError(
      );
      else throw err;
    }
    return flag;
  }

  exp = async (point: EcPoint, scalar: bigint): Promise<EcPoint> => new EcPoint(
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
      unpacked = new EcPoint(this.curve.ExtendedPoint.fromHex(bytes));
    } catch (err: any) {
      throw new BadPointError(`bad encoding: ${err.message}`)
    }
    return unpacked;
  }

  unpackValid = async (bytes: Uint8Array): Promise<EcPoint> => {
    const unpacked = this.unpack(bytes);
    await this.validatePoint(unpacked);
    return unpacked;
  }
}


export const initElliptic = (
  system: Elliptic.ED25519 | Elliptic.ED448 | Elliptic.JUBJUB
): EcGroup => {
  const mapping = {
    [Elliptic.ED25519]: ed25519,
    [Elliptic.ED448]: ed448,
    [Elliptic.JUBJUB]: jubjub,
  }
  return new EcGroup(system, mapping[system]);
}
