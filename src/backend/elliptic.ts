import type { CurvePoint, CurvePointCons } from '@noble/curves/abstract/curve.js';
import { pippenger } from '@noble/curves/abstract/curve.js';
import { ed25519, ed25519_hasher, ristretto255, ristretto255_hasher } from '@noble/curves/ed25519.js';
import { ed448, ed448_hasher, decaf448, decaf448_hasher } from '@noble/curves/ed448.js';
import { jubjub, jubjub_findGroupHash } from '@noble/curves/misc.js';
import { secp256k1, secp256k1_hasher } from '@noble/curves/secp256k1.js';
import {
  p256, p256_hasher, p384, p384_hasher, p521, p521_hasher
} from '@noble/curves/nist.js';
import { concatBytes, asciiToBytes } from '@noble/curves/utils.js';

import { Elliptic } from '../enums';
import { System } from '../types';
import { BadPointError } from '../errors';
import { Point, Group, validateMultiExp } from './abstract';


// noble's point types are F-bounded per curve; the backend relies only on
// the API they have in common
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type _CurvePoint = CurvePoint<bigint, any>;
type _PointCons = CurvePointCons<_CurvePoint>;


type _Codec = {
  toBytes: (point: _CurvePoint) => Uint8Array,
  fromBytes: (bytes: Uint8Array) => _CurvePoint,
};


/** Point of a built-in elliptic-curve backend, wrapping a noble point */
export class EcPoint implements Point {
  /** @internal Wrapped noble point */
  wrapped: _CurvePoint;
  private encode: _Codec['toBytes'];
  /** Canonical encoding of the backend's system */
  toBytes = (): Uint8Array => this.encode(this.wrapped);

  constructor(wrapped: _CurvePoint, encode: _Codec['toBytes']) {
    this.wrapped = wrapped;
    this.encode = encode;
  }

  /** Equality as elements of the curve, in variable time */
  equals = async <Q extends Point>(other: Q): Promise<boolean> => {
    // Not constant-time; compare canonical encodings with isEqualBytes where
    // secret-dependent points are involved
    return (other instanceof EcPoint) && (this.wrapped.equals(other.wrapped));
  }
}


type _HashToCurve = (msg: Uint8Array, dst: Uint8Array) => _CurvePoint;


/** Multiplications of the base point replacing noble's, where noble neither
 * blinds nor tables the base itself: `multiply` blinded, by a scalar in
 * [1, order), and `multiplyUnsafe` in variable time, by one in [0, order),
 * each throwing outside its range like noble's. blindsNatively then reports
 * the base as blinded */
type _BaseMultiplications = {
  multiply: (scalar: bigint) => _CurvePoint,
  multiplyUnsafe: (scalar: bigint) => _CurvePoint,
};


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


/** Built-in elliptic-curve backend over noble-curves; created by
 * `initBackend` */
export class EcGroup extends Group<EcPoint> {
  private base: _CurvePoint;
  private zero: _CurvePoint;
  private hashToCurve: _HashToCurve;
  private codec: _Codec;
  private blinding: _Blinding;
  private msmCutoff: number;
  private baseMultiplications?: _BaseMultiplications;
  /** @internal Point constructor of the noble curve */
  Point: _PointCons;

  constructor(
    system: System,
    Point: _PointCons,
    hashToCurve: _HashToCurve,
    codec: _Codec,
    blinding: _Blinding,
    msmCutoff: number,
    baseMultiplications?: _BaseMultiplications,
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
    this.msmCutoff = msmCutoff;
    this.baseMultiplications = baseMultiplications;
  }

  private wrap = (point: _CurvePoint): EcPoint => new EcPoint(point, this.codec.toBytes);

  /** By identity of the raw point, as noble recognizes its base */
  private isBase = (point: _CurvePoint): boolean => point === this.base;

  // SECURITY! points whose secret multiplication noble blinds
  blindsNatively = (point: EcPoint): boolean => this.blinding === 'all' ||
    (this.isBase(point.wrapped) &&
      (this.blinding === 'base' || this.baseMultiplications !== undefined));

  private assertOnCurve = (point: _CurvePoint): void => {
    try { point.assertValidity(); } catch (err: unknown) {
      if (err instanceof Error) throw new BadPointError(err.message);
      throw err;
    }
  }

  /** A point of the curve, possibly with a small-order component, whose
   * equality noble decides on the full curve */
  validateCurvePoint = async (point: EcPoint): Promise<boolean> => {
    if (!point.wrapped.is0()) this.assertOnCurve(point.wrapped);
    return true;
  }

  /** Accept points of the curve in the prime-order subgroup; throws
   * BadPointError otherwise */
  validatePoint = async (point: EcPoint): Promise<boolean> => {
    const wrapped = point.wrapped;
    if (wrapped.is0()) return true;
    this.assertOnCurve(wrapped);
    // SECURITY!
    // Reject points with a small-order component, which would otherwise
    // vanish from verification equations for suitable challenges
    if (!wrapped.isTorsionFree()) throw new BadPointError(
      'bad point: not in prime-order subgroup'
    );
    return true;
  }

  exp = async (point: EcPoint, scalar: bigint): Promise<EcPoint> => {
    if (scalar === 0n) return this.wrap(this.zero);
    if (this.baseMultiplications && this.isBase(point.wrapped)) return this.wrap(
      this.baseMultiplications.multiply(scalar)
    );
    return this.wrap(point.wrapped.multiply(scalar));
  }

  /** Variable-time multiplication of a raw point, through the base
   * multiplications for the base; shared by expPublic and multiExpPublic */
  private multiplyUnsafe = (point: _CurvePoint, scalar: bigint): _CurvePoint =>
    this.baseMultiplications && this.isBase(point) ?
      this.baseMultiplications.multiplyUnsafe(scalar) : point.multiplyUnsafe(scalar);

  /** Variable-time wNAF multiplication, whose cost shrinks with the scalar */
  expPublic = async (point: EcPoint, scalar: bigint): Promise<EcPoint> => this.wrap(
    this.multiplyUnsafe(point.wrapped, scalar)
  );

  /** Pippenger's method from `msmCutoff` points on, below which one
   * variable-time multiplication per point is faster */
  multiExpPublic = async (points: EcPoint[], scalars: bigint[]): Promise<EcPoint> => {
    validateMultiExp(points, scalars, this.order);
    const wrapped = points.map(point => point.wrapped);
    // PERFORMANCE! Pippenger's method from the cutoff on
    if (points.length >= this.msmCutoff) return this.wrap(
      pippenger(this.Point, wrapped, scalars)
    );
    // Inlines expPublic and operate on the raw points; keep in step with them
    return this.wrap(wrapped.reduce(
      (acc, point, i) => acc.add(this.multiplyUnsafe(point, scalars[i])), this.zero
    ));
  }

  /** Attach a table of window PRECOMPUTE_WINDOW, which noble builds on the
   * first multiplication and keeps per point object; returns the same point.
   * Setting a window drops the tables of the point, so the generator keeps
   * noble's own and points already prepared keep theirs */
  precomputeBase = (point: EcPoint): EcPoint => {
    const wrapped = point.wrapped;
    if (!this.isBase(wrapped) && !wrapped.is0() && !precomputed.has(wrapped)) {
      wrapped.precompute(PRECOMPUTE_WINDOW, true);
      precomputed.add(wrapped);
    }
    return point;
  }

  /** Point addition */
  operate = async (lhs: EcPoint, rhs: EcPoint): Promise<EcPoint> => this.wrap(
    lhs.wrapped.add(rhs.wrapped)
  );

  /** Point negation */
  invert = async (point: EcPoint): Promise<EcPoint> => this.wrap(
    point.wrapped.negate()
  );

  /** Decode a point of the curve, not checked to lie in the subgroup; throws
   * BadPointError on bytes that encode no point */
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


/** Number of points from which Pippenger's method beats one variable-time
 * multiplication per point, measured with noble 2.4.0 on every supported curve;
 * recheck on upgrades */
const MSM_CUTOFF = 4;


/** Window of the tables attached by precomputeBase. Against a window of 6, it
 * keeps 83-91% of the speedup at a third to half of the build time and memory
 * (from 107 KB on secp256k1 to 315 KB on p521 per point, built in 7 to 31 ms),
 * measured with noble 2.4.0; recheck on upgrades */
const PRECOMPUTE_WINDOW = 4;

// Points prepared by precomputeBase, across groups
const precomputed = new WeakSet<object>();


/** Supported curves; a new system needs an Elliptic member and an entry here.
 * The codec defaults to noble's native encoding, the MSM cutoff to MSM_CUTOFF
 * and the base multiplications to noble's */
const CURVES: Record<Elliptic, {
  Point: _PointCons,
  hashToCurve: _HashToCurve,
  codec?: (Point: _PointCons) => _Codec,
  blinding: _Blinding,
  msmCutoff?: number,
  base?: _BaseMultiplications,
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
    // PERFORMANCE!
    // noble never blinds it, since its Edwards base representative is twice
    // ed448's base but another object. Multiply that very object instead,
    // which noble blinds and tables, doubling the point rather than the secret
    // scalar. Same prime order, and the result lies in the prime-order subgroup
    blinding: 'none',
    base: {
      multiply: (scalar) => new decaf448.Point(ed448.Point.BASE.multiply(scalar).double()),
      // Likewise for public scalars, so as to use the table of ed448's base
      multiplyUnsafe: (scalar) => new decaf448.Point(
        ed448.Point.BASE.multiplyUnsafe(scalar).double()
      ),
    },
  },
  [Elliptic.SECP256K1]: {
    Point: secp256k1.Point,
    hashToCurve: (msg, DST) => secp256k1_hasher.hashToCurve(msg, { DST }),
    codec: sec1Codec,
    blinding: 'all',
    // Single multiplications use the endomorphism, and Pippenger's method
    // catches up only once noble widens its window at 16 points
    msmCutoff: 16,
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
  const {
    Point, hashToCurve, codec = nobleCodec, blinding, msmCutoff = MSM_CUTOFF,
    base,
  } = CURVES[system];
  return new EcGroup(
    system, Point, hashToCurve, codec(Point), blinding, msmCutoff, base,
  );
}
