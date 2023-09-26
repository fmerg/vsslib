import { Label } from '../types';
import { Algorithms } from '../enums';
import { Algorithm } from '../types';
import { Group, Point } from './abstract';
import { leInt2Buff, leBuff2Int } from '../utils';

const utils = require('../utils');

export type DlogPair = {
  u: Point,
  v: Point,
}

export type DlogProof = {
  commitments : Point[],
  response    : bigint,
}


export class CryptoSystem {
  _group:     Group;
  _label:     Label;
  _modulus:   bigint;
  _order:     bigint;
  _generator: Point;
  _neutral:   Point;

  _modBytes:  Uint8Array;
  _ordBytes:  Uint8Array;
  _genBytes:  Uint8Array;


  constructor(group: Group) {
    this._group     = group;
    this._label     = group.label;
    this._modulus   = group.modulus;
    this._order     = group.order;
    this._generator = group.generator;
    this._neutral   = group.neutral;

    this._modBytes  = leInt2Buff(this._modulus);
    this._ordBytes  = leInt2Buff(this._order);
    this._genBytes  = this._generator.toBytes();
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

  isEqual = async (ctx: CryptoSystem): Promise<Boolean> => {
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

  leBuffScalar = (buff: Uint8Array): bigint => {
    return (leBuff2Int(buff) as bigint) % this._order;
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

  pack = (p: Point): Uint8Array => {
    return this._group.pack(p);
  }

  unpack = (p: Uint8Array): Point => {
    return this._group.unpack(p);
  }

  hexify = (p: Point): string => {
    return this._group.hexify(p);
  }

  unhexify = (p: string): Point => {
    return this._group.unhexify(p);
  }

  fiatShamir = async (scalars: bigint[], points: Point[], algorithm?: Algorithm): Promise<Point> => {
    const fixedBuff = [
      this._modBytes,
      this._ordBytes,
      this._genBytes,
    ].reduce(
      (acc: number[], curr: Uint8Array) => [...acc, ...curr], []
    )
    const scalarsBuff = scalars.reduce(
      (acc: number[], s: bigint) => [...acc, ...leInt2Buff(s)], []
    );
    const pointsBuff = points.reduce(
      (acc: number[], p: Point) => [...acc, ...p.toBytes()], []
    );
    const digest = await utils.hash(
      new Uint8Array(
        [fixedBuff, scalarsBuff, pointsBuff].reduce(
          (acc, curr) => [...acc, ...curr], []
        )
      ),
      { algorithm: algorithm || Algorithms.DEFAULT }
    );
    const digestScalar = this.leBuffScalar(digest);
    return this._group.operate(digestScalar, this._generator);
  }

  prove_AND_Dlog = async (dlog: bigint, pairs: DlogPair[]): Promise<DlogProof> => {
    // TODO: Implement

    const commitments = [
      await this._group.randomPoint(),
      await this._group.randomPoint(),
    ];

    const response = await this._group.randomScalar();

    return {
      commitments,
      response,
    };
  }

  verify_AND_Dlog = async (pairs: DlogPair[], proof: DlogProof): Promise<Boolean> => {
    // TODO: Implement
    return true;
  }

  proveDlog = async (dlog: bigint, pair: DlogPair): Promise<DlogProof> => {
    return this.prove_AND_Dlog(dlog, [pair]);
  }

  verifyDlog = async (pair: DlogPair, proof: DlogProof): Promise<Boolean> => {
    return this.verify_AND_Dlog([pair], proof);
  }

}
