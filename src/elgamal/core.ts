import { Label } from '../types';
import { Algorithms } from '../enums';
import { Algorithm } from '../types';
import { Group, Point } from './abstract';
import { leInt2Buff, leBuff2Int, mod } from '../utils';

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
    const { label, modulus, order, generator, neutral } = group;
    this._group = group;
    this._label = label;
    this._modulus = modulus;
    this._order = order;
    this._generator = generator;
    this._neutral = neutral;
    this._modBytes = leInt2Buff(modulus);
    this._ordBytes = leInt2Buff(order);
    this._genBytes = generator.toBytes();
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
    return mod(leBuff2Int(buff), this._order);
  }

  fiatShamir = async (points: Point[], scalars: bigint[], opts?: { algorithm?: Algorithm }): Promise<bigint> => {
    const algorithm = opts ? (opts.algorithm || Algorithms.DEFAULT) : Algorithms.DEFAULT;
    const { _modBytes, _ordBytes, _genBytes } = this;
    const fixedBuff = [..._modBytes, ..._ordBytes, ..._genBytes];
    const pointsBuff = points.reduce((acc: number[], p: Point) => [...acc, ...p.toBytes()], []);
    const scalarsBuff = scalars.reduce((acc: number[], s: bigint) => [...acc, ...leInt2Buff(s)], []);

    const digest = await utils.hash(new Uint8Array([...fixedBuff, ...pointsBuff, ...scalarsBuff]), {
      algorithm
    });
    return this.leBuff2Scalar(digest);
  }

  proveEqDlog = async (z: bigint, pairs: DlogPair<P>[], opts?: { algorithm?: Algorithm }): Promise<DlogProof<P>> => {
    const algorithm = opts ? (opts.algorithm || Algorithms.DEFAULT) : Algorithms.DEFAULT;
    const { _group, _order } = this;

    const r = await _group.randomScalar();

    const commitments = [];
    for (const { u, v } of pairs) {
      commitments.push(await _group.operate(r, u));
    }

    const c = await this.fiatShamir(
      [
        ...pairs.reduce((acc: Point[], { u, v }: DlogPair<P>) => [...acc, u, v], []),
        ...commitments
      ],
      [],
      { algorithm }
    );

    const response = mod(r + c * z, _order);

    return { commitments, response, algorithm };
  }

  verifyEqDlog = async (pairs: DlogPair<P>[], proof: DlogProof<P>): Promise<boolean> => {
    const { commitments, response, algorithm } = proof;

    if (pairs.length !== commitments.length) {
      throw new Error('TODO');
    }

    const { _group } = this;

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
      const lhs = await _group.operate(response, u);
      const rhs = await _group.combine(
        commitments[i], await _group.operate(c, v)
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
    const { _group, _generator } = this;

    const randomness = await _group.randomScalar();
    const decryptor = await _group.operate(randomness, pub);

    const alpha = await _group.combine(decryptor, message);
    const beta = await _group.operate(randomness, _generator);

    return { ciphertext: { alpha, beta }, randomness, decryptor };
  }

  decrypt = async (ciphertext: Ciphertext<P>, opts: DecryptionOptions<P>): Promise<P> => {
    const { _group } = this;

    const { alpha, beta } = ciphertext;
    let { secret, decryptor, randomness, pub } = opts;

    decryptor = decryptor || (
      secret ? await _group.operate(secret, beta) : await _group.operate(randomness!, pub!)
    )
    const dInv = await _group.invert(decryptor);
    return _group.combine(alpha, dInv);
  }

  proveEncryption = async (ciphertext: Ciphertext<P>, randomness: bigint, opts?: { algorithm?: Algorithm }): Promise<DlogProof<P>> => {
    const algorithm = opts ? (opts.algorithm || Algorithms.DEFAULT) : Algorithms.DEFAULT;
    return this.proveDlog(randomness, this._generator,  ciphertext.beta, { algorithm });
  }

  verifyEncryption = async (ciphertext: Ciphertext<P>, proof: DlogProof<P>): Promise<boolean> => {
    return this.verifyDlog(this._generator, ciphertext.beta, proof);
  }

  proveDecryptor = async (ciphertext: Ciphertext<P>, secret: bigint, decryptor: P, opts?: { algorithm?: Algorithm }): Promise<DlogProof<P>> => {
    const { _group, _generator } = this;

    const pub = await _group.operate(secret, _generator);
    const algorithm = opts ? (opts.algorithm || Algorithms.DEFAULT) : Algorithms.DEFAULT;

    return this.proveDDH(secret, { u: ciphertext.beta, v: pub, w: decryptor }, { algorithm });
  }

  verifyDecryptor = async (decryptor: P, ciphertext: Ciphertext<P>, pub: P, proof: DlogProof<P>): Promise<boolean> => {
    return this.verifyDDH({ u: ciphertext.beta, v: pub, w: decryptor }, proof);
  }
}
