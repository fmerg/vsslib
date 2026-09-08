import { ed25519, ristretto255 } from '@noble/curves/ed25519.js';
import { ed448, decaf448 } from '@noble/curves/ed448.js';
import { jubjub } from '@noble/curves/misc.js';
import { System } from 'vsslib/types';


/** Little-endian encoding of `value` in `length` bytes */
const leBytes = (value: bigint, length: number): Uint8Array => {
  const out = new Uint8Array(length);
  for (let i = 0; i < length; i++, value >>= 8n) out[i] = Number(value & 0xffn);
  return out;
}


const leInt = (bytes: Uint8Array): bigint => bytes.reduceRight(
  (acc, byte) => (acc << 8n) | BigInt(byte), 0n
);


type _PointCons = { Fp: { ORDER: bigint }, ZERO: { toBytes(): Uint8Array }, BASE: { toBytes(): Uint8Array } };


/** Encodings of the neutral element with a field element left unreduced, i.e.
 * x + p in place of x; non-canonical, so they must be rejected */
const unreducedNeutral = (Point: _PointCons, x: bigint): Uint8Array[] => [
  leBytes(Point.Fp.ORDER + x, Point.ZERO.toBytes().length),
];


/** Non-canonical encodings for ristretto255 and decaf448, which encode a
 * non-negative field element s: s = p for the neutral element, and p - s
 * (negative) for the generator */
const primeOrderNonCanonical = (Point: _PointCons): Uint8Array[] => {
  const p = Point.Fp.ORDER;
  const length = Point.BASE.toBytes().length;
  return [
    ...unreducedNeutral(Point, 0n),
    leBytes(p - leInt(Point.BASE.toBytes()), length),
  ];
}


/** Encoding of the point (0, -1), which has order 2 on twisted Edwards curves */
const edwardsOrderTwo = (Point: typeof ed25519.Point) => Point.fromAffine(
  { x: 0n, y: Point.Fp.ORDER - 1n }
).toBytes();


export type SystemFixture = {
  scalarBytes: number,
  /** Default Pedersen base, pinned to catch changes of the derivation */
  defaultPedersenBase: string,
  /** Encoding of a point outside the prime-order subgroup; absent for prime-order groups */
  smallOrderPoint?: Uint8Array,
  /** Encodings that decode to a valid element under modular reduction but are not canonical */
  nonCanonicalPoints: Uint8Array[],
};


/** Per-system test data; a new system fails to compile until it has an entry */
export const fixtures: Record<System, SystemFixture> = {
  ed25519: {
    scalarBytes: 32,
    defaultPedersenBase: 'fed7bbcee7ed7e8101f3611762eb161ee9512f158699c1de88ccf6fc9711fabf',
    smallOrderPoint: edwardsOrderTwo(ed25519.Point),
    // y = 1 + p
    nonCanonicalPoints: unreducedNeutral(ed25519.Point, 1n),
  },
  ed448: {
    scalarBytes: 56,
    defaultPedersenBase: '9f20de8c2e08e3d1a7bfd2f871dbf122b05f521839c679559858d8966afd9453' +
      '1a4f8c63d2ca7ad0e59b4680bf55c65dba370bc40cc98e7880',
    smallOrderPoint: edwardsOrderTwo(ed448.Point),
    // y = 1 + p
    nonCanonicalPoints: unreducedNeutral(ed448.Point, 1n),
  },
  jubjub: {
    scalarBytes: 32,
    defaultPedersenBase: '1140a506c84387ceebb0d0167f6b2ef192dbc149662908a8a4998e4dd667f24c',
    smallOrderPoint: edwardsOrderTwo(jubjub.Point),
    // y = 1 + p
    nonCanonicalPoints: unreducedNeutral(jubjub.Point, 1n),
  },
  ristretto255: {
    scalarBytes: 32,
    defaultPedersenBase: 'a24deccc7db99bb9c3f0a913f14197e91d5f63ac34db72f2ef0feec65bfb8b19',
    nonCanonicalPoints: primeOrderNonCanonical(ristretto255.Point),
  },
  decaf448: {
    scalarBytes: 56,
    defaultPedersenBase: '74af30c8f1ba4f634abc0dd7a46bee804c023e0634a207808f4ece367b50d7b0' +
      '0d5eb9722a3a5c58be2827e6392a5b3ddcfa845ad3b33419',
    nonCanonicalPoints: primeOrderNonCanonical(decaf448.Point),
  },
};
