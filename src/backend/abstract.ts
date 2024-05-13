import { System } from '../types';
import { mod, leInt2Buff, leBuff2Int } from '../arith';

export interface Point {
  equals: (other: Point) => Promise<boolean>;
  toBytes: () => Uint8Array;
}

export abstract class Group<P extends Point> {
  system: System;
  modulus: bigint;
  order: bigint;
  generator: P;
  neutral: P;
  modBytes: Uint8Array;
  ordBytes: Uint8Array;
  genBytes: Uint8Array;

  constructor(system: System, modulus: bigint, order: bigint, generator: P, neutral: P) {
    this.system = system;
    this.modulus = modulus;
    this.order = order;
    this.generator = generator;;
    this.neutral = neutral;
    this.modBytes = leInt2Buff(modulus);
    this.ordBytes = leInt2Buff(order);
    this.genBytes = generator.toBytes();
  }

  leBuff2Scalar = (bytes: Uint8Array): bigint => mod(leBuff2Int(bytes), this.order);

  abstract equals<Q extends Point>(other: Group<Q>): Promise<boolean>;
  abstract randomScalar: () => Promise<bigint>;
  abstract randomScalarBuff: () => Promise<Uint8Array>;
  abstract randomPoint: () => Promise<P>;
  abstract validateScalar: (scalar: bigint, opts?: { raiseOnInvalid: boolean }) => Promise<boolean>;
  abstract validatePoint: (point: P, opts?: { raiseOnInvalid: boolean }) => Promise<boolean>;
  abstract operate: (scalar: bigint, point: P) => Promise<P>;
  abstract combine: (lhs: P, rhs: P) => Promise<P>;
  abstract invert: (point: P) => Promise<P>;
  abstract unpack: (bytes: Uint8Array) => P;
  abstract unpackValid: (bytes: Uint8Array) => Promise<P>;
  abstract generateSecret: (secret?: bigint) => Promise<{ secret: bigint, pub: Point }>;
}

