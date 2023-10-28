import { Label } from '../types';


export interface Point {
  isEqual: (other: Point) => Promise<boolean>;
  toBytes: () => Uint8Array;
  toHex: () => string;
}

export abstract class Group<P extends Point> {
  _label: Label;
  _modulus: bigint;
  _order: bigint;

  constructor(label: Label, modulus: bigint, order: bigint) {
    this._label = label;
    this._modulus = modulus;
    this._order = order;
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

  public abstract get generator(): P;
  public abstract get neutral(): P;
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

