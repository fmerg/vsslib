import type { CurvePoint, CurvePointCons } from '@noble/curves/abstract/curve.js';
import { ed25519, ed25519_hasher, ristretto255, ristretto255_hasher } from '@noble/curves/ed25519.js';
import { ed448, ed448_hasher, decaf448, decaf448_hasher } from '@noble/curves/ed448.js';
import { jubjub, jubjub_findGroupHash } from '@noble/curves/misc.js';
import { randomBytes, concatBytes, asciiToBytes } from '@noble/curves/utils.js';

import { Elliptic } from '../enums';
import { System } from '../types';
import { BadPointError, BadScalarError } from '../errors';
import { mod, leBytesToInt } from '../arith';
import { Point, Group } from './abstract';


// noble's point types are F-bounded per curve; the backend relies only on
// the API they have in common
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type _CurvePoint = CurvePoint<bigint, any>;
type _PointCons = CurvePointCons<_CurvePoint>;


class EcPoint implements Point {
  wrapped: _CurvePoint;
  toBytes = (): Uint8Array => this.wrapped.toBytes();

  constructor(wrapped: _CurvePoint) {
    this.wrapped = wrapped;
  }

  equals = async <Q extends Point>(other: Q): Promise<boolean> => {
    // TODO: Ensure that this is constant time
    return (other instanceof EcPoint) && (this.wrapped.equals(other.wrapped));
  }
}


type _HashToCurve = (msg: Uint8Array, dst: Uint8Array) => _CurvePoint;


// BLAKE2s personalization for the jubjub group hash
const JUBJUB_PERSONALIZATION = asciiToBytes('vsslib_H');


const jubjubHashToCurve: _HashToCurve = (msg, dst) => {
  if (dst.length > 255) throw new Error('DST too long');
  return jubjub_findGroupHash(
    concatBytes(Uint8Array.of(dst.length), dst, msg), JUBJUB_PERSONALIZATION
  );
}


export class EcGroup extends Group<EcPoint> {
  private base: _CurvePoint;
  private zero: _CurvePoint;
  private hashToCurve: _HashToCurve;
  Point: _PointCons;

  constructor(system: System, Point: _PointCons, hashToCurve: _HashToCurve) {
    const modulus = Point.Fp.ORDER;
    const order = Point.Fn.ORDER;
    const base = Point.BASE;
    const zero = Point.ZERO;
    const generator = new EcPoint(base);
    const neutral = new EcPoint(zero);
    super(system, modulus, order, generator, neutral);
    this.base = base;
    this.zero = zero;
    this.Point = Point;
    this.hashToCurve = hashToCurve;
  }

  // Reduce 128 extra bits modulo the order, so that the bias is negligible
  randomScalar = async (): Promise<bigint> => mod(
    leBytesToInt(randomBytes(this.scalarBytes + 16)),
    this.order
  );

  randomPoint = async (): Promise<EcPoint> => new EcPoint(
    this.base.multiply(await this.randomScalar())
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
      if (err instanceof Error) throw new BadPointError(err.message);
      throw err;
    }
    // Reject points with a small-order component, which would otherwise
    // vanish from verification equations for suitable challenges
    if (!point.wrapped.isTorsionFree()) throw new BadPointError(
      'bad point: not in prime-order subgroup'
    );
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

  bytesToPoint = (bytes: Uint8Array): EcPoint => {
    let point;
    try {
      point = new EcPoint(this.Point.fromBytes(bytes));
    } catch (err: unknown) {
      if (err instanceof Error) {
        throw new BadPointError(`bad encoding: ${err.message}`)
      }
      else throw err;
    }
    return point;
  }

  hashToPoint = async (msg: Uint8Array, dst: Uint8Array): Promise<EcPoint> => new EcPoint(
    this.hashToCurve(msg, dst)
  );
}


/** Supported curves; a new system needs an Elliptic member and an entry here */
const CURVES: Record<Elliptic, { Point: _PointCons, hashToCurve: _HashToCurve }> = {
  [Elliptic.ED25519]: {
    Point: ed25519.Point,
    hashToCurve: (msg, DST) => ed25519_hasher.hashToCurve(msg, { DST }),
  },
  [Elliptic.ED448]: {
    Point: ed448.Point,
    hashToCurve: (msg, DST) => ed448_hasher.hashToCurve(msg, { DST }),
  },
  [Elliptic.JUBJUB]: {
    Point: jubjub.Point,
    hashToCurve: jubjubHashToCurve,
  },
  [Elliptic.RISTRETTO255]: {
    Point: ristretto255.Point,
    hashToCurve: (msg, DST) => ristretto255_hasher.hashToCurve(msg, { DST }),
  },
  [Elliptic.DECAF448]: {
    Point: decaf448.Point,
    hashToCurve: (msg, DST) => decaf448_hasher.hashToCurve(msg, { DST }),
  },
};


export function initElliptic(system: Elliptic): EcGroup {
  const { Point, hashToCurve } = CURVES[system];
  return new EcGroup(system, Point, hashToCurve);
}
