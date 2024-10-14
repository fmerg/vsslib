import { Group, Point } from 'vsslib/backend';
import { Algorithm } from 'vsslib/types';
import { InvalidInput } from 'vsslib/errors';
import { mod, leInt2Buff, leBuff2Int } from 'vsslib/arith';
import { unpackScalar, unpackPoint } from 'vsslib/secrets';
import hash from 'vsslib/hash';


export type DlogPair<P extends Point> = { u: P, v: P };
export type DDHTuple<P extends Point> = { u: P, v: P, w: P };
export type GenericLinear<P extends Point> = { us: P[][], vs: P[] };
export type NizkProof = { commitment: Uint8Array[], response: Uint8Array[] };


export class NizkProtocol<P extends Point>{
  ctx: Group<P>;
  algorithm: Algorithm;

  constructor(ctx: Group<P>, algorithm: Algorithm) {
    this.ctx = ctx;
    this.algorithm = algorithm;
  }

  _unpackProof = async (proof: NizkProof): Promise<{ commitment: P[], response: bigint[] }> => {
    const { commitment, response } = proof;
    const m = commitment.length;
    const n = response.length;
    const innerComm = new Array(m);
    const innerResp = new Array(n);
    for (let i = 0; i < m; i++) innerComm[i] = await unpackPoint(this.ctx, commitment[i]);
    for (let i = 0; i < n; i++) innerResp[i] = await unpackScalar(this.ctx, response[i]);
    return { commitment: innerComm, response: innerResp };
  }

  _packProof = async (proof: { commitment: P[], response: bigint[] }): Promise<NizkProof> => {
    const commitment = proof.commitment.map(c => c.toBytes());
    const response = proof.response.map(r => leInt2Buff(r));
    return { commitment, response };
  }

  _computeChallenge = async (
    relation: GenericLinear<P>, commitment: P[], extras: Uint8Array[], nonce?: Uint8Array,
  ): Promise<bigint> => {
    const { modulus, order, generator } = this.ctx;
    const config = [...leInt2Buff(modulus), ...leInt2Buff(order), ...generator.toBytes()];
    const { us, vs } = relation;
    const statement = [
      ...us.reduce((acc, ui) => [...acc, ...ui], []),
      ...vs,
      ...commitment
    ].reduce(
      (acc: number[], p: P) => [...acc, ...p.toBytes()], []
    );
    const extrasBuff = extras.reduce((acc: number[], b: Uint8Array) => [...acc, ...b], []);
    nonce = nonce || Uint8Array.from([]);
    const digest = await hash(this.algorithm).digest(
      Uint8Array.from([
        ...config, ...statement, ...extrasBuff, ...nonce
      ])
    );
    return unpackScalar(this.ctx, digest);
  }

   _proveLinear = async (
    witness: bigint[], relation: GenericLinear<P>, extras: Uint8Array[], nonce?: Uint8Array,
  ): Promise<NizkProof> => {
    const exp = this.ctx.exp;
    const order = this.ctx.order;
    const { us, vs } = relation;
    const m = vs.length;
    const n = witness.length;
    const rs = new Array(n);
    for (let j = 0; j < n; j ++) rs[j] = await this.ctx.randomScalar();
    const commitment = new Array<P>(m);
    for (let i = 0; i < m; i++) {
      if (us[i].length !== n)
        throw new InvalidInput('Incompatible lengths');
      let ci = this.ctx.neutral;
      for (let j = 0; j < n; j++) {
        ci = await this.ctx.operate(
          ci,
          await exp(us[i][j], rs[j])
        );
      }
      commitment[i] = ci;
    }
    const challenge = await this._computeChallenge(
      relation, commitment, extras, nonce
    );
    const response = new Array(n);
    for (const [j, x] of witness.entries()) {
      response[j] = mod(rs[j] + x * challenge, order);
    }
    return this._packProof({ commitment, response });
  }

  _verifyLinear = async (
    relation: GenericLinear<P>, proof: NizkProof, extras: Uint8Array[], nonce?: Uint8Array
  ): Promise<boolean> => {
    const exp = this.ctx.exp;
    const { us, vs } = relation;
    const { commitment, response } = await this._unpackProof(proof);
    if (vs.length !== commitment.length)
      throw new InvalidInput('Incompatible lengths');
    const challenge = await this._computeChallenge(relation, commitment, extras, nonce);
    let flag = true;
    for (const [i, v] of vs.entries()) {
      if (us[i].length !== response.length)
        throw new InvalidInput('Incompatible lengths');
      const rhs = await this.ctx.operate(
        commitment[i],
        await exp(v, challenge)
      );
      let lhs = this.ctx.neutral;
      for (const [j, s] of response.entries()) {
        lhs = await this.ctx.operate(
          lhs,
          await exp(us[i][j], s)
        );
      }
      flag &&= await lhs.equals(rhs);
    }
    return flag;
  }

  /* Prove knowledge of `x_j`'s such that `v_i = Π_{j} u_ij ^ x_j` */
  proveLinear = async (
    witness: bigint[],
    relation: GenericLinear<P>,
    nonce?: Uint8Array,
    extras?: Uint8Array[]
  ): Promise<NizkProof> => {
    return this._proveLinear(
      witness,
      relation,
      extras || [],
      nonce
    );
  }

  verifyLinear = async (
    relation: GenericLinear<P>,
    proof: NizkProof,
    nonce?: Uint8Array,
    extras?: Uint8Array[]
  ): Promise<boolean> => {
    return this._verifyLinear(
      relation,
      proof,
      extras || [],
      nonce
    );
  }

  /* Prove knowledge of `x` such that `v = u ^ x` */
  proveDlog = async (x: bigint, { u, v }: DlogPair<P>, nonce?: Uint8Array): Promise<NizkProof> => {
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

  verifyDlog = async ({ u, v }: DlogPair<P>, proof: NizkProof, nonce?: Uint8Array): Promise<boolean> => {
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

  /* Prove knowledge of `z` such that `u = g ^ x`, `v = g ^ z` and `w = g ^ xz` */
  proveDDH = async (z: bigint, { u, v, w }: DDHTuple<P>, nonce?: Uint8Array): Promise<NizkProof> => {
    const g = this.ctx.generator;
    const n = this.ctx.neutral;
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

  verifyDDH = async ({ u, v, w }: DDHTuple<P>, proof: NizkProof, nonce?: Uint8Array): Promise<boolean> => {
    const g = this.ctx.generator;
    const n = this.ctx.neutral;
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
}

export default function<P extends Point>(ctx: Group<P>, algorithm: Algorithm) {
  return new NizkProtocol(ctx, algorithm);
}
