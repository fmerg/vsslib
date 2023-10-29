import { Label } from '../types';
import { Algorithms } from '../enums';
import { leInt2Buff, leBuff2Int, mod } from '../utils';

const utils = require('../utils');

export interface Point {
  isEqual: (other: Point) => Promise<boolean>;
  toBytes: () => Uint8Array;
  toHex: () => string;
}

export abstract class Group<P extends Point> {
  _label: Label;
  _modulus: bigint;
  _order: bigint;
  _generator: P;
  _neutral: P;
  _modBytes: Uint8Array;
  _ordBytes: Uint8Array;
  _genBytes: Uint8Array;

  constructor(label: Label, modulus: bigint, order: bigint, generator: P, neutral: P) {
    this._label = label;
    this._modulus = modulus;
    this._order = order;
    this._generator = generator;;
    this._neutral = neutral;
    this._modBytes = leInt2Buff(modulus);
    this._ordBytes = leInt2Buff(order);
    this._genBytes = generator.toBytes();
  }

  public get label(): Label {
    return this._label;
  }

  public get modulus(): bigint {
    return this._modulus;
  }

  public get order(): bigint {
    return this._order;
  }

  public get generator(): P {
    return this._generator;
  }

  public get neutral(): P {
    return this._neutral;
  }

  leBuff2Scalar = (buff: Uint8Array): bigint => {
    return mod(leBuff2Int(buff), this._order);
  }

  abstract isEqual<Q extends Point>(other: Group<Q>): Promise<boolean>;
  abstract assertEqual: (lhs: P, rhs: P) => Promise<boolean>;
  abstract assertValid: (point: P) => Promise<boolean>;
  abstract randomScalar: () => Promise<bigint>;
  abstract randomPoint: () => Promise<P>;
  abstract generatePoint: (scalar: bigint) => Promise<P>;
  abstract operate: (scalar: bigint, point: P) => Promise<P>;
  abstract combine: (lhs: P, rhs: P) => Promise<P>;
  abstract invert: (point: P) => Promise<P>;
  abstract unpack: (bytes: Uint8Array) => P;
  abstract unhexify: (hexnum: string) => P;

}

