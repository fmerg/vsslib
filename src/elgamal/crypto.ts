import { Label } from '../types';
import { Algorithms } from '../enums';
import { Algorithm } from '../types';
import { Group, Point } from './abstract';
import { leInt2Buff, leBuff2Int } from '../utils';

const utils = require('../utils');

export type DlogPair<P extends Point> = {
  u: P,
  v: P,
};

export type DDHTuple<P extends Point>= {
  u: P,
  v: P,
  w: P,
}

export type DlogProof<P extends Point> = {
  commitments: P[],
  response: bigint,
  algorithm: Algorithm,
}

export type Ciphertext<P extends Point>= {
  alpha: P,
  beta: P
}

export type DecryptionOptions<P>= {
  secret: bigint,
  decryptor?: never,
  randomness?: never,
  pub?: never,
} | {
  secret?: never,
  decryptor: P,
  randomness?: never,
  pub?: never,
} | {
  secret?: never,
  decryptor?: never,
  randomness: bigint,
  pub: P,
}


export class CryptoSystem<P extends Point, G extends Group<P>> {
  _group: Group<P>;
  _label: Label;
  _modulus: bigint;
  _order: bigint;
  _generator: P;
  _neutral: P;
  _modBytes: Uint8Array;
  _ordBytes: Uint8Array;
  _genBytes: Uint8Array;


  constructor(group: G) {
    this._group = group;
    this._label = group.label;
    this._modulus = group.modulus;
    this._order = group.order;
    this._generator = group.generator;
    this._neutral = group.neutral;
    this._modBytes = leInt2Buff(this._modulus);
    this._ordBytes = leInt2Buff(this._order);
    this._genBytes = this._generator.toBytes();
  }

  public get group(): Group<P> {
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

  public get generator(): P {
    return this._generator;
  }

  public get neutral(): P {
    return this._neutral;
  }

  async isEqual<Q extends Point>(other: CryptoSystem<Q, Group<Q>>): Promise<boolean> {
    return this._group.isEqual(other.group);
  }

  assertValid = async (point: P): Promise<boolean> => {
    return this._group.assertValid(point);
  }

  randomScalar = async (): Promise<bigint> => {
    return this._group.randomScalar();
  }

  randomPoint = async (): Promise<P> => {
    return this._group.randomPoint();
  }

  generatePoint = async (scalar: bigint): Promise<P> => {
    return this._group.generatePoint(scalar);
  }

  operate = async (scalar: bigint, point: P): Promise<P> => {
    return this._group.operate(scalar, point);
  }

  combine = async (lhs: P, rhs: P): Promise<P> => {
    return this._group.combine(lhs, rhs);
  }

  invert = async (point: P): Promise<P> => {
    return this._group.invert(point);
  }

  unpack = (bytes: Uint8Array): P => {
    return this._group.unpack(bytes);
  }

  unhexify = (hexnum: string): P => {
    return this._group.unhexify(hexnum);
  }

  leBuff2Scalar = (buff: Uint8Array): bigint => {
    // TODO: Apply mod function
    return (leBuff2Int(buff) as bigint) % this._order;
  }

  fiatShamir = async (points: Point[], scalars: bigint[], opts?: { algorithm?: Algorithm }): Promise<bigint> => {
    const algorithm = opts ? (opts.algorithm || Algorithms.DEFAULT) : Algorithms.DEFAULT;

    const fixedBuff = [...this._modBytes, ...this._ordBytes, ...this._genBytes];
    const pointsBuff = points.reduce((acc: number[], p: Point) => [...acc, ...p.toBytes()], []);
    const scalarsBuff = scalars.reduce((acc: number[], s: bigint) => [...acc, ...leInt2Buff(s)], []);

    const digest = await utils.hash(new Uint8Array([...fixedBuff, ...pointsBuff, ...scalarsBuff]), {
      algorithm
    });
    return this.leBuff2Scalar(digest);
  }

  proveEqDlog = async (z: bigint, pairs: DlogPair<P>[], opts?: { algorithm?: Algorithm }): Promise<DlogProof<P>> => {
    const algorithm = opts ? (opts.algorithm || Algorithms.DEFAULT) : Algorithms.DEFAULT;

    const r = await this._group.randomScalar();

    const commitments = [];
    for (const { u, v } of pairs) {
      commitments.push(await this._group.operate(r, u));
    }

    const c = await this.fiatShamir(
      [
        ...pairs.reduce((acc: Point[], { u, v }: DlogPair<P>) => [...acc, u, v], []),
        ...commitments
      ],
      [],
      { algorithm }
    );

    // TODO: Apply mod function
    const response = (r + c * z) % this._order;

    return { commitments, response, algorithm };
  }

  verifyEqDlog = async (pairs: DlogPair<P>[], proof: DlogProof<P>): Promise<boolean> => {
    const { commitments, response, algorithm } = proof;

    if (pairs.length !== commitments.length) {
      throw new Error('TODO');
    }

    const c = await this.fiatShamir(
      [
        ...pairs.reduce((acc: Point[], { u, v }: DlogPair<P>) => [...acc, u, v], []),
        ...commitments
      ],
      [],
      { algorithm }
    );

    let flag = true;
    for (const [i, { u, v }] of pairs.entries()) {
      const lhs = await this._group.operate(response, u);
      const rhs = await this._group.combine(
        commitments[i], await this._group.operate(c, v)
      );
      flag &&= await lhs.isEqual(rhs);
    }
    return flag;
  }

  proveDlog = async (z: bigint, u: P, v: P, opts?: { algorithm?: Algorithm }): Promise<DlogProof<P>> => {
    const algorithm = opts ? (opts.algorithm || Algorithms.DEFAULT) : Algorithms.DEFAULT;
    return this.proveEqDlog(z, [{ u, v }], { algorithm });
  }

  verifyDlog = async (u: P, v: P, proof: DlogProof<P>): Promise<boolean> => {
    return this.verifyEqDlog([{ u, v }], proof);
  }

  proveDDH = async (z: bigint, ddh: DDHTuple<P>, opts?: { algorithm?: Algorithm }): Promise<DlogProof<P>> => {
    const { u, v, w } = ddh;
    const algorithm = opts ? (opts.algorithm || Algorithms.DEFAULT) : Algorithms.DEFAULT;

    return this.proveEqDlog(z, [{ u: this._generator, v }, { u, v: w }], { algorithm });
  }

  verifyDDH = async (ddh: DDHTuple<P>, proof: DlogProof<P>): Promise<boolean> => {
    const { u, v, w } = ddh;

    return this.verifyEqDlog([{ u: this._generator, v }, { u, v: w }], proof);
  }

  encrypt = async (message: P, pub: P): Promise<{ ciphertext: Ciphertext<P>, randomness: bigint, decryptor: P }> => {
    const randomness = await this._group.randomScalar();
    const k = await this._group.operate(randomness, pub);

    const alpha = await this._group.combine(k, message);
    const beta = await this._group.operate(randomness, this._generator);

    return { ciphertext: { alpha, beta }, randomness, decryptor: k };
  }

  decrypt = async (ciphertext: Ciphertext<P>, opts: DecryptionOptions<P>): Promise<P> => {
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

    // TODO: Avoid casting
    const decryptorInverse = await this._group.invert(decryptor as P);
    return this._group.combine(alpha, decryptorInverse);
  }

  proveEncryption = async (ciphertext: Ciphertext<P>, randomness: bigint, opts?: { algorithm?: Algorithm }): Promise<DlogProof<P>> => {
    const algorithm = opts ? (opts.algorithm || Algorithms.DEFAULT) : Algorithms.DEFAULT;
    return this.proveDlog(randomness, this._generator,  ciphertext.beta, { algorithm });
  }

  verifyEncryption = async (ciphertext: Ciphertext<P>, proof: DlogProof<P>): Promise<boolean> => {
    return this.verifyDlog(this._generator, ciphertext.beta, proof);
  }

  proveDecryptor = async (ciphertext: Ciphertext<P>, secret: bigint, decryptor: P, opts?: { algorithm?: Algorithm }): Promise<DlogProof<P>> => {
    const pub = await this._group.operate(secret, this._generator);
    const algorithm = opts ? (opts.algorithm || Algorithms.DEFAULT) : Algorithms.DEFAULT;

    return this.proveDDH(secret, { u: ciphertext.beta, v: pub, w: decryptor }, { algorithm });
  }

  verifyDecryptor = async (decryptor: P, ciphertext: Ciphertext<P>, pub: P, proof: DlogProof<P>): Promise<boolean> => {
    return this.verifyDDH({ u: ciphertext.beta, v: pub, w: decryptor }, proof);
  }
}
