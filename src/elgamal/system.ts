import { Label } from '../types';
import { Group, Point } from './abstract';


export class Cryptosystem {
  _group:     Group;
  _label:     Label;
  _modulus:   bigint;
  _order:     bigint;
  _generator: Point;
  _neutral:   Point;

  constructor(group: Group) {
    this._group     = group;
    this._label     = group.label;
    this._modulus   = group.modulus;
    this._order     = group.order;
    this._generator = group.generator;
    this._neutral   = group.neutral;
  }

  public get group(): Group {
    return this._group;
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

  public get generator(): Point {
    return this._generator;
  }

  public get neutral(): Point {
    return this._neutral;
  }

  isEqual = async (ctx: Cryptosystem): Promise<Boolean> => {
    return this._group.isEqual(ctx._group);
  }

  operate = async (s: bigint, p: Point): Promise<Point> => {
    return this._group.operate(s, p);
  }

  combine = async (p: Point, q: Point): Promise<Point> => {
    return this._group.combine(p, q);
  }

  invert = async (p: Point): Promise<Point> => {
    return this._group.invert(p);
  }

  randomScalar = async (): Promise<bigint> => {
    return this._group.randomScalar();
  }

  randomPoint = async (): Promise<Point> => {
    return this._group.randomPoint();
  }

  generatePoint = async (scalar: bigint): Promise<Point> => {
    return this._group.generatePoint(scalar);
  }

  assertValid = async (p: Point): Promise<Boolean> => {
    return await this._group.assertValid(p);
  }

  packPoint = async (p: Point): Promise<string> => {
    return this._group.packPoint(p);
  }

  unpackPoint = async (p: string): Promise<Point> => {
    return this._group.unpackPoint(p);
  }

}
