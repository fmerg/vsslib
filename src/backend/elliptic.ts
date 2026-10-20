import type { CurvePoint, CurvePointCons } from '@noble/curves/abstract/curve.js';
import { ed25519, ed25519_hasher, ristretto255, ristretto255_hasher } from '@noble/curves/ed25519.js';
import { ed448, ed448_hasher, decaf448, decaf448_hasher } from '@noble/curves/ed448.js';
import { jubjub, jubjub_findGroupHash } from '@noble/curves/misc.js';
import { secp256k1, secp256k1_hasher } from '@noble/curves/secp256k1.js';
import {
  p256, p256_hasher, p384, p384_hasher, p521, p521_hasher
} from '@noble/curves/nist.js';
import { randomBytes } from '@noble/hashes/utils.js';
import { concatBytes, asciiToBytes } from '@noble/curves/utils.js';

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


type _Codec = {
  toBytes: (point: _CurvePoint) => Uint8Array,
  fromBytes: (bytes: Uint8Array) => _CurvePoint,
};


export class EcPoint implements Point {
  /** @internal Wrapped noble point */
  wrapped: _CurvePoint;
  private encode: _Codec['toBytes'];
  toBytes = (): Uint8Array => this.encode(this.wrapped);

  constructor(wrapped: _CurvePoint, encode: _Codec['toBytes']) {
    this.wrapped = wrapped;
    this.encode = encode;
  }

  equals = async <Q extends Point>(other: Q): Promise<boolean> => {
    // Not constant-time; compare canonical encodings with isEqualBytes where
    // secret-dependent points are involved
    return (other instanceof EcPoint) && (this.wrapped.equals(other.wrapped));
  }
}


type _HashToCurve = (msg: Uint8Array, dst: Uint8Array) => _CurvePoint;


/** Points whose secret multiplication noble blinds: every point on cofactor-1
 * curves, otherwise only its base point, recognized by identity (see
 * shouldBlind in @noble/curves/abstract/curve.js; recheck on upgrades) */
type _Blinding = 'all' | 'base' | 'none';


// BLAKE2s personalization for the jubjub group hash
const JUBJUB_PERSONALIZATION = asciiToBytes('vsslib_H');


/** Encoding native to noble, e.g. RFC 8032 for Edwards curves */
const nobleCodec = (Point: _PointCons): _Codec => ({
  toBytes: (point) => point.toBytes(),
  fromBytes: (bytes) => Point.fromBytes(bytes),
});


/** Compressed SEC1 encoding, with the single byte 0x00 for the point at
 * infinity, which noble does not encode; noble compresses by default */
const sec1Codec = (Point: _PointCons): _Codec => ({
  toBytes: (point) => point.is0() ? Uint8Array.of(0) : point.toBytes(),
  fromBytes: (bytes) => (bytes.length === 1 && bytes[0] === 0) ?
    Point.ZERO : Point.fromBytes(bytes),
});


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
  private codec: _Codec;
  private blinding: _Blinding;
  /** @internal Point constructor of the noble curve */
  Point: _PointCons;

  constructor(
    system: System,
    Point: _PointCons,
    hashToCurve: _HashToCurve,
    codec: _Codec,
    blinding: _Blinding,
  ) {
    const modulus = Point.Fp.ORDER;
    const order = Point.Fn.ORDER;
    const base = Point.BASE;
    const zero = Point.ZERO;
    const generator = new EcPoint(base, codec.toBytes);
    const neutral = new EcPoint(zero, codec.toBytes);
    super(system, modulus, order, generator, neutral);
    this.base = base;
    this.zero = zero;
    this.Point = Point;
    this.hashToCurve = hashToCurve;
    this.codec = codec;
    this.blinding = blinding;
  }

  private wrap = (point: _CurvePoint): EcPoint => new EcPoint(point, this.codec.toBytes);

  // Reduce 128 extra bits modulo the order, so that the bias is negligible,
  // and wipe the random bytes, which determine the scalar
  randomScalar = async (): Promise<bigint> => {
    const bytes = randomBytes(this.scalarBytes + 16);
    const scalar = mod(leBytesToInt(bytes), this.order);
    bytes.fill(0);
    return scalar;
  }

  randomPoint = async (): Promise<EcPoint> => this.expSecret(
    this.generator, await this.randomScalar()
  );

  blindsNatively = (point: EcPoint): boolean => this.blinding === 'all' ||
    (this.blinding === 'base' && point.wrapped === this.base);

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

  exp = async (point: EcPoint, scalar: bigint): Promise<EcPoint> => this.wrap(
    scalar !== 0n ? point.wrapped.multiply(scalar) : this.zero
  );

  /** Variable-time wNAF multiplication, whose cost shrinks with the scalar */
  expPublic = async (point: EcPoint, scalar: bigint): Promise<EcPoint> => this.wrap(
    point.wrapped.multiplyUnsafe(scalar)
  );

  operate = async (lhs: EcPoint, rhs: EcPoint): Promise<EcPoint> => this.wrap(
    lhs.wrapped.add(rhs.wrapped)
  );

  invert = async (point: EcPoint): Promise<EcPoint> => this.wrap(
    point.wrapped.negate()
  );

  bytesToPoint = (bytes: Uint8Array): EcPoint => {
    let point;
    try {
      point = this.wrap(this.codec.fromBytes(bytes));
    } catch (err: unknown) {
      if (err instanceof Error) {
        throw new BadPointError(`bad encoding: ${err.message}`)
      }
      else throw err;
    }
    return point;
  }

  hashToPoint = async (msg: Uint8Array, dst: Uint8Array): Promise<EcPoint> => this.wrap(
    this.hashToCurve(msg, dst)
  );
}


/** Supported curves; a new system needs an Elliptic member and an entry here.
 * The codec defaults to noble's native encoding */
const CURVES: Record<Elliptic, {
  Point: _PointCons,
  hashToCurve: _HashToCurve,
  codec?: (Point: _PointCons) => _Codec,
  blinding: _Blinding,
}> = {
  [Elliptic.ED25519]: {
    Point: ed25519.Point,
    hashToCurve: (msg, DST) => ed25519_hasher.hashToCurve(msg, { DST }),
    blinding: 'base',
  },
  [Elliptic.ED448]: {
    Point: ed448.Point,
    hashToCurve: (msg, DST) => ed448_hasher.hashToCurve(msg, { DST }),
    blinding: 'base',
  },
  [Elliptic.JUBJUB]: {
    Point: jubjub.Point,
    hashToCurve: jubjubHashToCurve,
    blinding: 'base',
  },
  [Elliptic.RISTRETTO255]: {
    Point: ristretto255.Point,
    hashToCurve: (msg, DST) => ristretto255_hasher.hashToCurve(msg, { DST }),
    // Multiplies its Edwards representative, whose base is ed25519's
    blinding: 'base',
  },
  [Elliptic.DECAF448]: {
    Point: decaf448.Point,
    hashToCurve: (msg, DST) => decaf448_hasher.hashToCurve(msg, { DST }),
    // Its Edwards base representative is not ed448's base, so noble never blinds
    blinding: 'none',
  },
  [Elliptic.SECP256K1]: {
    Point: secp256k1.Point,
    hashToCurve: (msg, DST) => secp256k1_hasher.hashToCurve(msg, { DST }),
    codec: sec1Codec,
    blinding: 'all',
  },
  [Elliptic.P256]: {
    Point: p256.Point,
    hashToCurve: (msg, DST) => p256_hasher.hashToCurve(msg, { DST }),
    codec: sec1Codec,
    blinding: 'all',
  },
  [Elliptic.P384]: {
    Point: p384.Point,
    hashToCurve: (msg, DST) => p384_hasher.hashToCurve(msg, { DST }),
    codec: sec1Codec,
    blinding: 'all',
  },
  [Elliptic.P521]: {
    Point: p521.Point,
    hashToCurve: (msg, DST) => p521_hasher.hashToCurve(msg, { DST }),
    codec: sec1Codec,
    blinding: 'all',
  },
};


export function initElliptic(system: Elliptic): EcGroup {
  const { Point, hashToCurve, codec = nobleCodec, blinding } = CURVES[system];
  return new EcGroup(system, Point, hashToCurve, codec(Point), blinding);
}
