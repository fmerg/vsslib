import { Label } from '../common';
import { Algorithms } from '../enums';
import { leInt2Buff, leBuff2Int, mod } from '../utils';

const utils = require('../utils');

export interface Point {
  isEqual: (other: Point) => Promise<boolean>;
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

  abstract isEqual<Q extends Point>(other: Group<Q>): Promise<boolean>;
  abstract randomBytes: () => Promise<Uint8Array>;
  abstract randomScalar: () => Promise<bigint>;
  abstract randomPoint: () => Promise<P>;
  abstract validateBytes: (bytes: Uint8Array) => Promise<boolean>;
  abstract validateScalar: (scalar: bigint) => Promise<boolean>;
  abstract validatePoint: (point: P) => Promise<boolean>;
  abstract operate: (scalar: bigint, point: P) => Promise<P>;
  abstract combine: (lhs: P, rhs: P) => Promise<P>;
  abstract invert: (point: P) => Promise<P>;
  abstract unpack: (bytes: Uint8Array) => P;
  abstract unhexify: (hexnum: string) => P;
  abstract generateKeypair: (secret?: bigint) => Promise<{ secret: bigint, point: Point }>;
}

