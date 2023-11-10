import { Point, Group } from '../backend/abstract';
import { BasePolynomial } from './base';
import { Messages } from './enums';
import { mod, modInv, Messages as utilMessages } from '../utils';
import { byteLen, randBigint } from '../utils';
const backend = require('../backend');


const __0n = BigInt(0);
const __1n = BigInt(1);


export class Polynomial<P extends Point> extends BasePolynomial {
  ctx: Group<P>;
  constructor(ctx: Group<P>, coeffs: bigint[]) {
    super(coeffs, ctx.order);
    this.ctx = ctx;
  }


  async generateFeldmannCommitments(): Promise<P[]> {
    const { operate, generator } = this.ctx;
    const commitments = new Array(this.degree + 1);
    for (const [index, coeff] of this.coeffs.entries()) {
      commitments[index] = await operate(coeff, generator);
    }
    return commitments;
  }

  async generatePedersenCommitments(h: P): Promise<{ commitments: P[], bs: bigint[] }>{
    const degree = this.degree;
    const { order, generator: g, combine, operate } = this.ctx;
    const coeffs = new Array(degree + 1);
    const nrBytes = byteLen(order);
    for (let i = 0; i < coeffs.length; i++) {
      coeffs[i] = await randBigint(nrBytes);
    }
    const polynomial2 = new Polynomial(this.ctx, coeffs);
    const commitments = new Array(degree + 1);
    const bs = new Array(degree + 1);
    for (const [i, a] of this.coeffs.entries()) {
      const b = polynomial2.coeffs[i];
      commitments[i] = await combine(
        await operate(a, g),
        await operate(b, h),
      );
      bs[i] = await polynomial2.evaluate(i);
    }
    return { bs, commitments };
  }
}


export async function verifyFeldmannCommitments<P extends Point>(
  ctx: Group<P>,
  secret: bigint,
  index: number,
  commitments: P[],
): Promise<boolean> {
  const { order, generator, neutral, operate, combine } = ctx;
  const target = await operate(secret, generator);
  let acc = neutral;
  const i = index;
  for (const [j, comm] of commitments.entries()) {
    const curr = await operate(mod(BigInt(i ** j), order), comm);
    acc = await combine(acc, curr);
  }
  return await acc.isEqual(target);
}


export async function verifyPedersenCommitments<P extends Point>(
  ctx: Group<P>,
  secret: bigint,
  index: number,
  b: bigint,
  h: P,
  commitments: P[],
): Promise<boolean> {
  const { order, generator: g, neutral, operate, combine } = ctx;
  const lhs = await combine(
    await operate(secret, g),
    await operate(b, h),
  );
  let rhs = neutral;
  const i = index;
  for (const [j, c] of commitments.entries()) {
    rhs = await combine(rhs, await operate(BigInt(i ** j), c));
  }
  return await lhs.isEqual(rhs);
}
