import { Algorithms } from '../enums';
import { Algorithm } from '../types';
import { Group, Point } from '../backend/abstract';
import { mod } from '../crypto/arith';
import { FiatShamir } from './fiatShamir';

export type DlogLinear<P extends Point> = {
  us: P[][],
  vs: P[],
}

export type NizkProof<P extends Point> = {
  commitments: P[],
  response: bigint[],
  algorithm: Algorithm,
}

export abstract class NizkProtocol<P extends Point> extends FiatShamir<P> {

  abstract prove: (witnesses: any, relation: any, nonce?: Uint8Array) => Promise<NizkProof<P>>;
  abstract verify: (relation: any, proof: NizkProof<P>, nonce?: Uint8Array) => Promise<boolean>;

  async proveLinearRelation(witnesses: bigint[], relation: DlogLinear<P>, extras: Uint8Array[], nonce?: Uint8Array): Promise<NizkProof<P>> {
    const { ctx: { order, randomScalar, neutral, operate, combine }, algorithm } = this;
    const { us, vs } = relation;
    const m = vs.length;
    const n = witnesses.length;
    const rs = new Array(n);
    for (let j = 0; j < n; j ++) {
      rs[j] = await randomScalar();
    }
    const commitments = new Array(m);
    for (let i = 0; i < m; i++) {
      if (us[i].length !== n) throw new Error('Invalid dimensions');
      let ci = neutral;
      for (let j = 0; j < n; j++) {
        ci = await combine(ci, await operate(rs[j], us[i][j]));
      }
      commitments[i] = ci;
    }
    const challenge = await this.computeChallenge(
      [
        ...us.reduce((acc, ui) => [...acc, ...ui], []),
        ...vs,
        ...commitments,
      ],
      [],
      extras,
      nonce,
    );
    const response = new Array(n);
    for (const [j, x] of witnesses.entries()) {
      response[j] = mod(rs[j] + x * challenge, order);
    }
    return { commitments, response, algorithm };
  }

  async verifyLinearRelation(relation: DlogLinear<P>, proof: NizkProof<P>, extras: Uint8Array[], nonce?: Uint8Array): Promise<boolean> {
    const { neutral, operate, combine } = this.ctx;
    const { us, vs } = relation;
    const { commitments, response, algorithm } = proof;
    if (vs.length !== commitments.length) throw new Error('Invalid dimensions');
    const challenge = await this.computeChallenge(
      [
        ...us.reduce((acc, ui) => [...acc, ...ui], []),
        ...vs,
        ...commitments,
      ],
      [],
      extras,
      nonce,
      algorithm,
    );
    let flag = true;
    for (const [i, v] of vs.entries()) {
      if (us[i].length !== response.length) throw new Error('Invalid dimensions');
      const rhs = await combine(commitments[i], await operate(challenge, v));
      let lhs = neutral;
      for (const [j, s] of response.entries()) {
        lhs = await combine(lhs, await operate(s, us[i][j]));
      }
      flag &&= await lhs.equals(rhs);
    }
    return flag;
  }
}
