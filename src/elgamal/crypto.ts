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

export type DDHTuple = {
  u: Point,
  v: Point,
  w: Point,
}

export type DlogProof = {
  commitments : Point[],
  response    : bigint,
  algorithm   : Algorithm,
}

export type Ciphertext = {
  alpha:  Point,
  beta:   Point
}

export type DecryptionOptions = {
  secret: bigint,
  decryptor?: never,
  randomness?: never,
  pub?: never,
} | {
  secret?: never,
  decryptor: Point,
  randomness?: never,
  pub?: never,
} | {
  secret?: never,
  decryptor?: never,
  randomness: bigint,
  pub: Point,
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

  fiatShamir = async (points: Point[], scalars: bigint[], algorithm?: Algorithm): Promise<bigint> => {
    const fixedBuff = [
      this._modBytes,
      this._ordBytes,
      this._genBytes,
    ].reduce(
      (acc: number[], curr: Uint8Array) => [...acc, ...curr], []
    )
    const pointsBuff = points.reduce(
      (acc: number[], p: Point) => [...acc, ...p.toBytes()], []
    );
    const scalarsBuff = scalars.reduce(
      (acc: number[], s: bigint) => [...acc, ...leInt2Buff(s)], []
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

  prove_AND_Dlog = async (dlog: bigint, pairs: DlogPair[], algorithm?: Algorithm): Promise<DlogProof> => {
    algorithm = algorithm || Algorithms.DEFAULT;

    const r = await this._group.randomScalar();

    const commitments = [];
    for (const { u, v } of pairs) {
      commitments.push(await this._group.operate(r, u));
    }

    const c = await this.fiatShamir(
      [
        ...pairs.reduce((acc: Point[], { u, v }: DlogPair) => [...acc, u, v], []),
        ...commitments
      ],
      [],
      algorithm
    );

    const response = (r + c * dlog) % this._order;

    return { commitments, response, algorithm };
  }

  verify_AND_Dlog = async (pairs: DlogPair[], proof: DlogProof): Promise<Boolean> => {
    const { commitments, response, algorithm } = proof;

    const c = await this.fiatShamir(
      [
        ...pairs.reduce((acc: Point[], { u, v }: DlogPair) => [...acc, u, v], []),
        ...commitments
      ],
      [],
      algorithm
    );

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

  proveDlog = async (dlog: bigint, pair: DlogPair, algorithm?: Algorithm): Promise<DlogProof> => {
    return this.prove_AND_Dlog(dlog, [pair], algorithm);
  }

  verifyDlog = async (pair: DlogPair, proof: DlogProof): Promise<Boolean> => {
    return this.verify_AND_Dlog([pair], proof);
  }

  proveDDH = async (dlog: bigint, ddh: DDHTuple, algorithm?: Algorithm): Promise<DlogProof> => {
    const { u, v, w } = ddh;

    return this.prove_AND_Dlog(
      dlog,
      [
        {
          u: this._generator,
          v: v,
        },
        {
          u: u,
          v: w,
        },
      ],
      algorithm || Algorithms.DEFAULT
    );
  }

  verifyDDH = async (ddh: DDHTuple, proof: DlogProof): Promise<Boolean> => {
    const { u, v, w } = ddh;

    return this.verify_AND_Dlog(
      [
        {
          u: this._generator,
          v: v,
        },
        {
          u: u,
          v: w,
        },
      ],
      proof
    );
  }

  encrypt = async (message: Point, pub: Point): Promise<{
    ciphertext: Ciphertext,
    randomness: bigint,
    decryptor: Point,
  }> => {
    const randomness = await this._group.randomScalar();
    const k = await this._group.operate(randomness, pub);

    const alpha = await this._group.combine(k, message);
    const beta = await this._group.operate(randomness, this._generator);

    return { ciphertext: { alpha, beta }, randomness, decryptor: k };
  }

  decrypt = async (ciphertext: Ciphertext, opts: DecryptionOptions): Promise<Point> => {
    const { alpha, beta } = ciphertext;
    let decryptor;

    if (opts.secret) {
      decryptor = await this._group.operate(opts.secret, beta);
    }

    if (opts.randomness) {
      decryptor = await this._group.operate(opts.randomness, opts.pub);
    }

    if (opts.decryptor) {
      decryptor = opts.decryptor;
    }

    const decryptorInverse = await this._group.invert(decryptor as Point);
    const plaintext = await this._group.combine(alpha, decryptorInverse);

    return plaintext;
  }

  proveDecryptor = async (ciphertext: Ciphertext, secret: bigint, decryptor: Point, algorithm?: Algorithm): Promise<DlogProof> => {
    const pub = await this._group.operate(secret, this._generator);

    return await this.proveDDH(secret, { u: ciphertext.beta, v: pub, w: decryptor }, algorithm);
  }

  verifyDecryptor = async (decryptor: Point, ciphertext: Ciphertext, pub: Point, proof: DlogProof): Promise<Boolean> => {
    return await this.verifyDDH({ u: ciphertext.beta, v: pub, w: decryptor }, proof);
  }

  proveRandomness = async (ciphertext: Ciphertext, randomness: bigint, algorithm?: Algorithm): Promise<DlogProof> => {
  }

  verifyRandomness = async (ciphertext: Ciphertext, proof: DlogProof): Promise<Boolean> => {
  }
}
