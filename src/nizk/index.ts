import { Algorithm } from '../types';
import { Group, Point } from '../backend/abstract';
import { mod } from '../crypto/arith';
import { leInt2Buff, leBuff2Int } from '../crypto/bitwise';

import hash from '../crypto/hash';


export type DlogPair<P extends Point> = {
  u: P,
  v: P,
};

export type DDHTuple<P extends Point> = {
  u: P,
  v: P,
  w: P,
}

export type GenericLinear<P extends Point> = {
  us: P[][],
  vs: P[],
}

export type NizkProof = {
  commitments: Uint8Array[],
  response: bigint[],
}

type InnerProof<P extends Point> = {
  commitments: P[],
  response: bigint[],
}


export class NizkProtocol<P extends Point>{
  ctx: Group<P>;
  algorithm: Algorithm;

  constructor(ctx: Group<P>, algorithm: Algorithm) {
    this.ctx = ctx;
    this.algorithm = algorithm;
  }

  fillMatrix = (m: number, n: number, pt: P): P[][] => Array.from({ length: m }, (_, i) =>
    Array.from({ length: n }, (_, i) => pt)
  )

  toInner = async (proof: NizkProof): Promise<InnerProof<P>> => {
    const { commitments: buffers, response } = proof;
    const m = buffers.length;
    const commitments = new Array(m);
    const { unpack, validatePoint } = this.ctx;
    for (let i = 0; i < m; i++) {
      const c = unpack(buffers[i]);
      await validatePoint(c);
      commitments[i] = c;
    }
    return { commitments, response };
  }

  toOuter = async (proof: InnerProof<P>): Promise<NizkProof> => {
    const { commitments, response } = proof;
    return {
      commitments: commitments.map(c => c.toBytes()),
      response
    }
  }

  computeChallenge = async (points: P[], extras: Uint8Array[], nonce?: Uint8Array): Promise<
    bigint
  > => {
    const { modBytes, ordBytes, genBytes, leBuff2Scalar } = this.ctx;
    const configBuff = [...modBytes, ...ordBytes, ...genBytes];
    const pointsBuff = points.reduce(
      (acc: number[], p: P) => [...acc, ...p.toBytes()], []
    );
    const extrasBuff = extras.reduce(
      (acc: number[], b: Uint8Array) => [...acc, ...b], []
    );
    nonce = nonce || Uint8Array.from([]);
    const digest = await hash(this.algorithm).digest(Uint8Array.from([
      ...configBuff, ...pointsBuff, ...extrasBuff, ...nonce
    ]));
    return leBuff2Scalar(digest);
  }

   _proveLinear = async (
    witnesses: bigint[], relation: GenericLinear<P>, extras: Uint8Array[], nonce?: Uint8Array
  ): Promise<NizkProof> => {
    const { order, randomScalar, neutral, operate, combine } = this.ctx;
    const { us, vs } = relation;
    const m = vs.length;
    const n = witnesses.length;
    const rs = new Array(n);
    for (let j = 0; j < n; j ++) {
      rs[j] = await randomScalar();
    }
    const commitments = new Array(m);
    for (let i = 0; i < m; i++) {
      if (us[i].length !== n)
        throw new Error('Incompatible lengths');
      let ci = neutral;
      for (let j = 0; j < n; j++) {
        ci = await combine(
          ci,
          await operate(rs[j], us[i][j])
        );
      }
      commitments[i] = ci;
    }
    const challenge = await this.computeChallenge(
      [
        ...us.reduce((acc, ui) => [...acc, ...ui], []),
        ...vs,
        ...commitments,
      ],
      extras,
      nonce,
    );
    const response = new Array(n);
    for (const [j, x] of witnesses.entries()) {
      response[j] = mod(rs[j] + x * challenge, order);
    }
    return this.toOuter({ commitments, response });
  }

  _verifyLinear = async (
    relation: GenericLinear<P>, proof: NizkProof, extras: Uint8Array[], nonce?: Uint8Array
  ): Promise<boolean> => {
    const { neutral, operate, combine } = this.ctx;
    const { us, vs } = relation;
    const { commitments, response } = await this.toInner(proof);
    if (vs.length !== commitments.length)
      throw new Error('Incompatible lengths');
    const challenge = await this.computeChallenge(
      [
        ...us.reduce((acc, ui) => [...acc, ...ui], []),
        ...vs,
        ...commitments,
      ],
      extras,
      nonce,
    );
    let flag = true;
    for (const [i, v] of vs.entries()) {
      if (us[i].length !== response.length)
        throw new Error('Incompatible lengths');
      const rhs = await combine(
        commitments[i],
        await operate(challenge, v)
      );
      let lhs = neutral;
      for (const [j, s] of response.entries()) {
        lhs = await combine(
          lhs,
          await operate(s, us[i][j])
        );
      }
      flag &&= await lhs.equals(rhs);
    }
    return flag;
  }

  proveLinear = async (
    witnesses: bigint[], relation: GenericLinear<P>, nonce?: Uint8Array, extras?: Uint8Array[]
  ): Promise<NizkProof> => {
    return this._proveLinear(
      witnesses,
      relation,
      extras || [],
      nonce
    );
  }

  verifyLinear = async (
    relation: GenericLinear<P>, proof: NizkProof, nonce?: Uint8Array, extras?: Uint8Array[]
  ): Promise<boolean> => {
    return this._verifyLinear(
      relation,
      proof,
      extras || [],
      nonce
    );
  }

  proveDlog = async (x: bigint, { u, v }: DlogPair<P>, nonce?: Uint8Array): Promise<
    NizkProof
  > => {
    return this._proveLinear(
      [x],
      {
        us: [[u]],
        vs: [v]
      },
      [],
      nonce
    );
  }

  verifyDlog = async ({ u, v }: DlogPair<P>, proof: NizkProof, nonce?: Uint8Array): Promise<
    boolean
  > => {
    return this._verifyLinear(
      {
        us: [[u]],
        vs: [v]
      },
      proof,
      [],
      nonce
    );
  }

  proveAndDlog = async (witnesses: bigint[], pairs: DlogPair<P>[], nonce?: Uint8Array): Promise<
    NizkProof
  > => {
    const m = pairs.length;
    const us = this.fillMatrix(m, m, this.ctx.neutral);
    for (let i = 0; i < m; i++) {
      us[i][i] = pairs[i].u;
    }
    return this._proveLinear(
      witnesses,
      {
        us,
        vs: pairs.map(({ v }) => v),
      },
      [],
      nonce
    );
  }

  verifyAndDlog = async (pairs: DlogPair<P>[], proof: NizkProof, nonce?: Uint8Array): Promise<
    boolean
  > => {
    const m = pairs.length;
    const us = this.fillMatrix(m, m, this.ctx.neutral);
    for (let i = 0; i < m; i++) {
      us[i][i] = pairs[i].u;
    }
    return this._verifyLinear(
      {
        us,
        vs: pairs.map(({ v }) => v),
      },
      proof,
      [],
      nonce
    );
  }

  proveEqDlog = async (x: bigint, pairs: DlogPair<P>[], nonce?: Uint8Array): Promise<NizkProof> => {
    const m = pairs.length;
    const witnesses = Array.from({ length: m }, (_, i) => x);
    const us = this.fillMatrix(m, m, this.ctx.neutral);
    for (let i = 0; i < m; i++) {
      us[i][i] = pairs[i].u;
    }
    return this._proveLinear(
      witnesses,
      {
        us,
        vs: pairs.map(({ v }) => v),
      },
      [],
      nonce
    );
  }

  verifyEqDlog = async (pairs: DlogPair<P>[], proof: NizkProof, nonce?: Uint8Array): Promise<
    boolean
  > => {
    const m = pairs.length;
    const us = this.fillMatrix(m, m, this.ctx.neutral);
    for (let i = 0; i < m; i++) {
      us[i][i] = pairs[i].u;
    }
    return this._verifyLinear(
      {
        us,
        vs: pairs.map(({ v }) => v),
      },
      proof,
      [],
      nonce
    );
  }

  proveDDH = async (z: bigint, { u, v, w }: DDHTuple<P>, nonce?: Uint8Array): Promise<
    NizkProof
  > => {
    const { generator: g, neutral: n } = this.ctx;
    return this._proveLinear(
      [z, z],
      {
        us: [[g, n], [n, u]],
        vs: [v, w]
      },
      [],
      nonce
    );
  }

  verifyDDH = async ({ u, v, w }: DDHTuple<P>, proof: NizkProof, nonce?: Uint8Array): Promise<
    boolean
  > => {
    const { generator: g, neutral: n } = this.ctx;
    return this._verifyLinear(
      {
        us: [[g, n], [n, u]],
        vs: [v, w]
      },
      proof,
      [],
      nonce
    );
  }

  proveRepresentation = async (
    witnesses: { s: bigint, t: bigint }, commitment: { h: P, u: P }, nonce?: Uint8Array
  ): Promise<NizkProof> => {
    const { s, t } = witnesses;
    const { h, u } = commitment;
    const { generator: g } = this.ctx;
    return this._proveLinear(
      [s, t],
      {
        us: [[g, h]],
        vs: [u]
      },
      [],
      nonce
    );
  }

  verifyRepresentation = async (
    commitment: { h: P, u: P }, proof: NizkProof, nonce?: Uint8Array
  ): Promise<boolean> => {
    const { h, u } = commitment;
    const { generator: g } = this.ctx;
    return this._verifyLinear(
      {
        us: [[g, h]],
        vs: [u]
      },
      proof,
      [],
      nonce
    );
  }
}

export default function<P extends Point>(ctx: Group<P>, algorithm: Algorithm) {
  return new NizkProtocol(ctx, algorithm);
}
