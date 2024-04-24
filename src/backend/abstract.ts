import { Label } from '../schemes';
import { mod } from '../crypto/arith';
import { leInt2Buff, leBuff2Int } from '../crypto/bitwise';

export interface Point {
  equals: (other: Point) => Promise<boolean>;
  toBytes: () => Uint8Array;
  toHex: () => string;
}

export abstract class Group<P extends Point> {
  label: Label;
  modulus: bigint;
  order: bigint;
  generator: P;
  neutral: P;
  modBytes: Uint8Array;
  ordBytes: Uint8Array;
  genBytes: Uint8Array;

  constructor(label: Label, modulus: bigint, order: bigint, generator: P, neutral: P) {
    this.label = label;
    this.modulus = modulus;
    this.order = order;
    this.generator = generator;;
    this.neutral = neutral;
    this.modBytes = leInt2Buff(modulus);
    this.ordBytes = leInt2Buff(order);
    this.genBytes = generator.toBytes();
  }

  leBuff2Scalar = (bytes: Uint8Array): bigint => {
    return mod(leBuff2Int(bytes), this.order);
  }

  abstract equals<Q extends Point>(other: Group<Q>): Promise<boolean>;
  abstract randomBytes: () => Promise<Uint8Array>;
  abstract randomScalar: () => Promise<bigint>;
  abstract randomPoint: () => Promise<P>;
  abstract validateBytes: (bytes: Uint8Array, opts?: { raiseOnInvalid: boolean }) => Promise<boolean>;
  abstract validateScalar: (scalar: bigint, opts?: { raiseOnInvalid: boolean }) => Promise<boolean>;
  abstract validatePoint: (point: P, opts?: { raiseOnInvalid: boolean }) => Promise<boolean>;
  abstract operate: (scalar: bigint, point: P) => Promise<P>;
  abstract combine: (lhs: P, rhs: P) => Promise<P>;
  abstract invert: (point: P) => Promise<P>;
  abstract unpack: (bytes: Uint8Array) => P;
  abstract unhexify: (hexnum: string) => P;
  abstract generateKeypair: (secret?: bigint) => Promise<{ secret: bigint, pub: Point }>;
}

