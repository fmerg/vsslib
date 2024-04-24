import { Point, Group } from '../backend/abstract';
import { mod, modInv } from '../crypto/arith';
import {
  BaseShare,
  BaseSharing,
  verifyFeldmann as _verifyFeldmann,
  verifyPedersen as _verifyPedersen
} from '../base';

const lagrange = require('../lagrange');

const __0n = BigInt(0);
const __1n = BigInt(1);


export class SecretShare<P extends Point> implements BaseShare<bigint> {
  value: bigint;
  index: number;

  constructor(value: bigint, index: number) {
    this.value = value;
    this.index = index;
  }
};


export class PubShare<P extends Point> implements BaseShare<P> {
  value: P;
  index: number;

  constructor(value: P, index: number) {
    this.value = value;
    this.index = index;
  }
};


export class SecretSharing<P extends Point> extends BaseSharing<
  bigint, P, SecretShare<P>, PubShare<P>
> {

  getSecretShares = async (): Promise<SecretShare<P>[]> => {
    const { polynomial, nrShares } = this;
    const shares = [];
    for (let index = 1; index <= nrShares; index++) {
      const value = polynomial.evaluate(index);
      shares.push({ value, index });
    }
    return shares;
  }

  getPublicShares = async (): Promise<PubShare<P>[]> => {
    const { nrShares, polynomial: { evaluate }, ctx: { operate, generator } } = this;
    const shares = [];
    for (let index = 1; index <= nrShares; index++) {
      const value = await operate(evaluate(index), generator);
      shares.push({ value, index });
    }
    return shares;
  }

};


export class ShamirParty<P extends Point> {
  ctx: Group<P>;

  constructor(ctx: Group<P>) {
    this.ctx = ctx;
  }

  validateThreshold = (nrShares: number, predefined: [bigint, bigint][], threshold: number) => {
    if (nrShares < 1) throw new Error('Number of shares must be at least 1');
    if (threshold < 1) throw new Error('Threshold parameter must be at least 1');
    if (threshold > nrShares) throw new Error('Threshold cannot exceed number of shares');
    if (nrShares > this.ctx.order) throw new Error('Number of shares cannot exceed the group order');
    if (predefined.length >= threshold) throw new Error('Number of predefined points violates threshold');
  }

  shareSecret = async (
    nrShares: number, threshold: number, secret: bigint, predefined?: [bigint, bigint][]
  ): Promise<SecretSharing<P>> => {
    predefined = predefined || [];
    this.validateThreshold(nrShares, predefined, threshold);
    const xyPoints = new Array(threshold);
    xyPoints[0] = [__0n, secret];
    let index = 1;
    while (index < threshold) {
      const x = index;
      const y = index <= predefined.length ? predefined[index - 1] : await this.ctx.randomScalar();
      xyPoints[index] = [x, y];
      index++;
    }
    const polynomial = await lagrange.interpolate(this.ctx, xyPoints);
    return new SecretSharing<P>(this.ctx, nrShares, threshold, polynomial);
  }

  verifyFeldmann = async (share: SecretShare<P>, commitments: P[]): Promise<boolean> => {
    const { value: secret, index } = share;
    return _verifyFeldmann(this.ctx, secret, index, commitments);
  }

   verifyPedersen = async (
    share: SecretShare<P>, binding: bigint, pub: P, commitments: P[],
  ): Promise<boolean> => {
    const { value: secret, index } = share;
    return _verifyPedersen(this.ctx, secret, binding, index, pub, commitments);
  }

  computeLambda = (index: number, qualifiedIndexes: number[]): bigint => {
    let lambda = __1n;
    const { order } = this.ctx
    const i = index;
    qualifiedIndexes.forEach(j => {
      if (i != j) {
        const curr = BigInt(j) * modInv(BigInt(j - i), order);
        lambda = mod(lambda * curr, order);
      }
    });
    return lambda;
  }

  reconstructSecret = (qualifiedShares: SecretShare<P>[]): bigint => {
    const { order } = this.ctx;
    const indexes = qualifiedShares.map(share => share.index);
    return qualifiedShares.reduce((acc, share) => {
      const { value, index } = share;
      const lambda = this.computeLambda(index, indexes);
      return mod(acc + value * lambda, order);
    }, __0n);
  }

  reconstructPublic = async (qualifiedShares: PubShare<P>[]): Promise<P> => {
    const { order, combine, neutral, operate } = this.ctx;
    const indexes = qualifiedShares.map(share => share.index);
    let acc = neutral;
    for (const { index, value } of qualifiedShares) {
      const lambda = this.computeLambda(index, indexes);
      acc = await combine(acc, await operate(lambda, value));
    }
    return acc;
  }
}


export default function<P extends Point>(ctx: Group<P>) {
  return new ShamirParty(ctx);
}
