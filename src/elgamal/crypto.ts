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

  leBuff2Scalar = (buff: Uint8Array): bigint => {
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

  fiatShamir = async (scalars: bigint[], points: Point[], algorithm?: Algorithm): Promise<bigint> => {
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

    return this.leBuff2Scalar(digest);
  }

  prove_AND_Dlog = async (dlog: bigint, pairs: DlogPair[]): Promise<DlogProof> => {
    const r = await this._group.randomScalar();
    const commitments = [];
    for (const { u, v } of pairs) {
      commitments.push(await this._group.operate(r, u));
    }

    const c = await this.fiatShamir([], commitments, Algorithms.SHA256);  // TODO: Enhance
    const response = (r + c * dlog) % this._order;

    return { commitments, response };
  }

  verify_AND_Dlog = async (pairs: DlogPair[], proof: DlogProof): Promise<Boolean> => {
    const { commitments, response } = proof;
    const c = await this.fiatShamir([], commitments);

    let flag: Boolean = true;
    for (const [i, { u, v }] of pairs.entries()) {
      const lpt = await this._group.operate(response, u);
      const rpt = await this._group.combine(
        commitments[i], await this._group.operate(c, v)
      );
      flag &&= await lpt.isEqual(rpt);
    }

    return flag;
  }

  proveDlog = async (dlog: bigint, pair: DlogPair): Promise<DlogProof> => {
    return this.prove_AND_Dlog(dlog, [pair]);
  }

  verifyDlog = async (pair: DlogPair, proof: DlogProof): Promise<Boolean> => {
    return this.verify_AND_Dlog([pair], proof);
  }

}
