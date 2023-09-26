import { Label } from '../types';
import { byteLen, randomInteger } from '../utils';


export abstract class Group {
  _label:   Label
  _modulus: bigint;
  _order:   bigint;

  constructor(label: Label, modulus: bigint, order: bigint) {
    this._label   = label;
    this._modulus = modulus;
    this._order   = order;
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

  public abstract get generator(): Point;
  public abstract get neutral(): Point;
  abstract isEqual: (g: Group) => Promise<Boolean>;
  abstract operate: (s: bigint, p: Point) => Promise<Point>;
  abstract combine: (p: Point, q: Point) => Promise<Point>;
  abstract invert: (p: Point) => Promise<Point>;
  abstract randomPoint: () => Promise<Point>;
  abstract generatePoint: (s: bigint) => Promise<Point>;
  abstract assertValid: (p: Point) => Promise<Boolean>;
  abstract assertEqual: (p: Point, q: Point) => Promise<Boolean>;
  abstract pack: (p: Point) => Uint8Array;
  abstract unpack: (p: Uint8Array) => Point;
  abstract hexify: (p: Point) => string;
  abstract unhexify: (p: string) => Point;

  randomScalar = async (): Promise<bigint> => {
    const size = byteLen(this._order);
    return (await randomInteger(size)) % this._order;
  }
}


export abstract class Point {
  _group: Group;

  constructor(group: Group) {
    this._group = group;
  }

  public get group(): Group {
    return this._group
  }

  isEqual = async (other: Point): Promise<Boolean> => {
    return (
      (await this._group.isEqual(other.group)) &&
      (await this._group.assertEqual(this, other))
    );
  }

  toBytes = (): Uint8Array => {
    return this._group.pack(this);
  }

  toHex = (): string => {
    return this._group.hexify(this);
  }
}
