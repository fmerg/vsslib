import { ExtPointType, CurveFn as _Curve } from '@noble/curves/abstract/edwards';
import { ed25519 } from '@noble/curves/ed25519';
import { ed448 } from '@noble/curves/ed448';
import { jubjub } from '@noble/curves/jubjub';

import { Elliptic } from '../enums';
import { System } from '../types';
import { BadPointError, BadScalarError } from '../errors';
import { mod, leBuff2Int } from '../arith';
import { Point, Group } from './abstract';


interface _CurvePoint extends ExtPointType { toRawBytes?: Function; };


class EcPoint implements Point {
  wrapped: _CurvePoint;
  toBytes = (): Uint8Array => this.wrapped.toRawBytes!();

  constructor(wrapped: _CurvePoint) {
    this.wrapped = wrapped;
  }

  equals = async <Q extends Point>(other: Q): Promise<boolean> => {
    // TODO: Ensure that this is constant time
    return (other instanceof EcPoint) && (this.wrapped.equals(other.wrapped));
  }
}


export class EcGroup extends Group<EcPoint> {
  private base: _CurvePoint;
  private zero: _CurvePoint;
  curve: _Curve;

  constructor(system: System, curve: _Curve) {
    const modulus = curve.CURVE.Fp.ORDER;
    const order = curve.CURVE.n;
    const base = curve.ExtendedPoint.BASE;
    const zero = curve.ExtendedPoint.ZERO;
    const generator = new EcPoint(base);
    const neutral = new EcPoint(zero);
    super(system, modulus, order, generator, neutral);
    this.base = base;
    this.zero = zero;
    this.curve = curve;
  }

  randomScalar = async (): Promise<bigint> => mod(
    leBuff2Int(this.curve.CURVE.randomBytes(this.curve.CURVE.Fp.BYTES)),
    this.order
  );

  randomPoint = async (): Promise<EcPoint> => new EcPoint(
    this.base.multiply(mod(
      leBuff2Int(this.curve.CURVE.randomBytes(this.curve.CURVE.Fp.BYTES)),
      this.order
    ))
  );

  validateScalar = async (scalar: bigint): Promise<boolean> => {
    const flag = 0 < scalar && scalar < this.order;
    if (!flag) throw new BadScalarError(
      `Scalar not in range`
    );
    return flag;
  }

  validatePoint = async (point: EcPoint): Promise<boolean> => {
    const flag = true;
    if (await point.wrapped.equals(this.zero)) return flag;
    try { point.wrapped.assertValidity(); } catch (err: unknown) {
      if (err instanceof Error && err.message.startsWith('bad point: '))
        throw new BadPointError(err.message);
      throw err;
    }
    return flag;
  }

  exp = async (point: EcPoint, scalar: bigint): Promise<EcPoint> => new EcPoint(
    scalar !== 0n ? point.wrapped.multiply(scalar) : this.zero
  );

  operate = async (lhs: EcPoint, rhs: EcPoint): Promise<EcPoint> => new EcPoint(
    lhs.wrapped.add(rhs.wrapped)
  );

  invert = async (point: EcPoint): Promise<EcPoint> => new EcPoint(
    point.wrapped.negate()
  );

  buff2Point = (bytes: Uint8Array): EcPoint => {
    let point;
    try {
      point = new EcPoint(this.curve.ExtendedPoint.fromHex(bytes));
    } catch (err: unknown) {
      if (err instanceof Error) {
        throw new BadPointError(`bad encoding: ${err.message}`)
      }
      else throw err;
    }
    return point;
  }
}


export function initElliptic(
  system: Elliptic.ED25519 | Elliptic.ED448 | Elliptic.JUBJUB
): EcGroup {
  const mapping = {
    [Elliptic.ED25519]: ed25519,
    [Elliptic.ED448]: ed448,
    [Elliptic.JUBJUB]: jubjub,
  }
  return new EcGroup(system, mapping[system]);
}
