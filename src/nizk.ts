/** @module vsslib/nizk */

import { Group, Point } from './backend';
import { Algorithm } from './types';
import { InvalidInput } from './errors';
import { mod, intToLeBytes, leBytesToInt } from './arith';
import { hash } from './hash';


export type DlogPair<P extends Point> = { u: P, v: P };
export type DDHTuple<P extends Point> = { u: P, v: P, w: P };
export type GenericLinear<P extends Point> = { us: P[][], vs: P[] };
export type NizkProof = { commitment: Uint8Array[], response: Uint8Array[] };

type ProofType = 'linear' | 'dlog' | 'ddh';


/** Unambiguous encoding of a sequence of fields, each prefixed by its length */
function encodeFields(fields: Uint8Array[]): Uint8Array {
  const lengths = fields.map(f => intToLeBytes(BigInt(f.length), 4));
  const out = new Uint8Array(fields.reduce((acc, f) => acc + 4 + f.length, 0));
  let offset = 0;
  for (const [i, f] of fields.entries()) {
    out.set(lengths[i], offset);
    out.set(f, offset + 4);
    offset += 4 + f.length;
  }
  return out;
}

const encodeCount = (n: number): Uint8Array => intToLeBytes(BigInt(n), 4);


export class NizkProtocol<P extends Point>{
  ctx: Group<P>;
  algorithm: Algorithm;

  constructor(ctx: Group<P>, algorithm: Algorithm) {
    this.ctx = ctx;
    this.algorithm = algorithm;
  }

  private unpackProof = async (proof: NizkProof): Promise<{ commitment: P[], response: bigint[] }> => {
    const { commitment, response } = proof;
    const m = commitment.length;
    const n = response.length;
    const innerComm = new Array(m);
    const innerResp = new Array(n);
    // Only compared with elements of the subgroup, so that a small-order
    // component makes verification fail without a subgroup check, as long as
    // the relation points are subgroup elements
    for (let i = 0; i < m; i++) innerComm[i] = await this.ctx.parseCurvePoint(commitment[i]);
    for (let i = 0; i < n; i++) innerResp[i] = await this.ctx.parseScalar(response[i]);
    return { commitment: innerComm, response: innerResp };
  }

  private packProof = async (proof: { commitment: P[], response: bigint[] }): Promise<NizkProof> => {
    const commitment = proof.commitment.map(c => c.toBytes());
    const response = proof.response.map(r => this.ctx.scalarToBytes(r));
    return { commitment, response };
  }

  private computeChallenge = async (
    type: ProofType,
    relation: GenericLinear<P>,
    commitment: P[],
    extras: Uint8Array[],
    nonce?: Uint8Array,
  ): Promise<bigint> => {
    const { modulus, order, generator } = this.ctx;
    const { us, vs } = relation;
    const toBytes = (p: P) => p.toBytes();
    const input = encodeFields([
      new TextEncoder().encode(`vsslib:nizk:${type}`),
      intToLeBytes(modulus),
      intToLeBytes(order),
      generator.toBytes(),
      encodeCount(us.length),
      ...us.flatMap(ui => [encodeCount(ui.length), ...ui.map(toBytes)]),
      encodeCount(vs.length),
      ...vs.map(toBytes),
      encodeCount(commitment.length),
      ...commitment.map(toBytes),
      encodeCount(extras.length),
      ...extras,
      nonce || new Uint8Array(),
    ]);
    const digest = await hash(this.algorithm).digest(input);
    return mod(leBytesToInt(digest), order);
  }

  /* Prove knowledge of `x_j`'s such that `v_i = Π_{j} u_ij ^ x_j` */
  proveLinear = async (
    witness: bigint[],
    relation: GenericLinear<P>,
    nonce?: Uint8Array,
    extras: Uint8Array[] = [],
  ): Promise<NizkProof> => this.prove('linear', witness, relation, nonce, extras);

  verifyLinear = async (
    relation: GenericLinear<P>,
    proof: NizkProof,
    nonce?: Uint8Array,
    extras: Uint8Array[] = [],
  ): Promise<boolean> => this.verify('linear', relation, proof, nonce, extras);

  private prove = async (
    type: ProofType,
    witness: bigint[],
    relation: GenericLinear<P>,
    nonce?: Uint8Array,
    extras: Uint8Array[] = [],
  ): Promise<NizkProof> => {
    const order = this.ctx.order;
    const { us, vs } = relation;
    if (us.length !== vs.length)
      throw new InvalidInput('Incompatible lengths');
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
          await this.ctx.expSecret(us[i][j], rs[j])
        );
      }
      commitment[i] = ci;
    }
    const challenge = await this.computeChallenge(
      type, relation, commitment, extras, nonce
    );
    const response = new Array(n);
    for (const [j, x] of witness.entries()) {
      response[j] = mod(rs[j] + x * challenge, order);
    }
    return this.packProof({ commitment, response });
  }

  private verify = async (
    type: ProofType,
    relation: GenericLinear<P>,
    proof: NizkProof,
    nonce?: Uint8Array,
    extras: Uint8Array[] = [],
  ): Promise<boolean> => {
    const { us, vs } = relation;
    if (us.length !== vs.length)
      throw new InvalidInput('Incompatible lengths');
    const { commitment, response } = await this.unpackProof(proof);
    if (vs.length !== commitment.length)
      throw new InvalidInput('Incompatible lengths');
    const challenge = await this.computeChallenge(type, relation, commitment, extras, nonce);
    // Relation, challenge and responses are public, so that variable time is
    // safe: check `Π_j u_ij ^ s_j * v_i ^ (-c) = commitment_i` by one
    // multi-exponentiation per row
    const exponents = [...response, mod(-challenge, this.ctx.order)];
    let flag = true;
    for (const [i, v] of vs.entries()) {
      if (us[i].length !== response.length)
        throw new InvalidInput('Incompatible lengths');
      const lhs = await this.ctx.multiExpPublic([...us[i], v], exponents);
      flag &&= await lhs.equals(commitment[i]);
    }
    return flag;
  }

  /* Prove knowledge of `x` such that `v = u ^ x` */
  proveDlog = async (
    x: bigint, { u, v }: DlogPair<P>, nonce?: Uint8Array, extras: Uint8Array[] = [],
  ): Promise<NizkProof> => {
    return this.prove(
      'dlog',
      [x],
      {
        us: [[u]],
        vs: [v]
      },
      nonce,
      extras,
    );
  }

  verifyDlog = async (
    { u, v }: DlogPair<P>, proof: NizkProof, nonce?: Uint8Array, extras: Uint8Array[] = [],
  ): Promise<boolean> => {
    return this.verify(
      'dlog',
      {
        us: [[u]],
        vs: [v]
      },
      proof,
      nonce,
      extras,
    );
  }

  /* Prove knowledge of `z` such that `u = g ^ x`, `v = g ^ z` and `w = g ^ xz` */
  proveDDH = async (z: bigint, { u, v, w }: DDHTuple<P>, nonce?: Uint8Array): Promise<NizkProof> => {
    const g = this.ctx.generator;
    const n = this.ctx.neutral;
    return this.prove(
      'ddh',
      [z, z],
      {
        us: [[g, n], [n, u]],
        vs: [v, w]
      },
      nonce,
    );
  }

  verifyDDH = async ({ u, v, w }: DDHTuple<P>, proof: NizkProof, nonce?: Uint8Array): Promise<boolean> => {
    const g = this.ctx.generator;
    const n = this.ctx.neutral;
    return this.verify(
      'ddh',
      {
        us: [[g, n], [n, u]],
        vs: [v, w]
      },
      proof,
      nonce,
    );
  }
}

export function nizk<P extends Point>(ctx: Group<P>, algorithm: Algorithm) {
  return new NizkProtocol(ctx, algorithm);
}
