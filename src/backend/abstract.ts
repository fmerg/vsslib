import { System } from 'vsslib/types';
import { mod, leBuff2Int } from 'vsslib/arith';

export interface Point {
  toBytes: () => Uint8Array;
  equals: (other: Point) => Promise<boolean>;
}

export abstract class Group<P extends Point> {
  system: System;
  modulus: bigint;
  order: bigint;
  generator: P;
  neutral: P;

  constructor(system: System, modulus: bigint, order: bigint, generator: P, neutral: P) {
    this.system = system;
    this.modulus = modulus;
    this.order = order;
    this.generator = generator;;
    this.neutral = neutral;
  }

  leBuff2Scalar = (bytes: Uint8Array): bigint => mod(leBuff2Int(bytes), this.order);

  abstract generateSecret: () => Promise<Uint8Array>;
  abstract randomScalar: () => Promise<bigint>;
  abstract randomPoint: () => Promise<P>;
  abstract validateScalar: (scalar: bigint) => Promise<boolean>;
  abstract validatePoint: (point: P) => Promise<boolean>;
  abstract exp: (point: P, scalar: bigint) => Promise<P>;
  abstract operate: (lhs: P, rhs: P) => Promise<P>;
  abstract invert: (point: P) => Promise<P>;
  abstract buff2Point: (bytes: Uint8Array) => P;
}

