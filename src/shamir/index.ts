import { Point, Group } from '../backend/abstract';
import { BaseShare, BaseSharing, verifyFeldmann, verifyPedersen } from '../vss';
import { Algorithms, Algorithm } from '../schemes';
import { mod, modInv } from '../utils';
const lagrange = require('../lagrange');

const __0n = BigInt(0);
const __1n = BigInt(1);


export class ScalarShare<P extends Point> implements BaseShare<bigint> {
  value: bigint;
  index: number;

  constructor(value: bigint, index: number) {
    this.value = value;
    this.index = index;
  }
};


export class PointShare<P extends Point> implements BaseShare<P> {
  value: P;
  index: number;

  constructor(value: P, index: number) {
    this.value = value;
    this.index = index;
  }
};


export class ScalarSharing<P extends Point> extends BaseSharing<
  bigint,
  P,
  ScalarShare<P>,
  PointShare<P>
> {

  getSecretShares = async (): Promise<ScalarShare<P>[]> => {
    const { polynomial, nrShares } = this;
    const shares = [];
    for (let index = 1; index <= nrShares; index++) {
      const value = polynomial.evaluate(index);
      shares.push({ value, index });
    }
    return shares;
  }

  getPublicShares = async (): Promise<PointShare<P>[]> => {
    const { nrShares, polynomial: { evaluate }, ctx: { operate, generator } } = this;
    const shares = [];
    for (let index = 1; index <= nrShares; index++) {
      const value = await operate(evaluate(index), generator);
      shares.push({ value, index });
    }
    return shares;
  }

};


export class ShamirDealer<P extends Point> {
  ctx: Group<P>;

  constructor(ctx: Group<P>) {
    this.ctx = ctx;
  }

  distribute = async (
    secret: bigint,
    nrShares: number,
    threshold: number,
    givenShares?: [bigint, bigint][],
  ): Promise<ScalarSharing<P>> => {
    givenShares = givenShares || [];
    if (threshold > nrShares) throw new Error('Threshold exceeds number of shares');
    if (threshold < 1) throw new Error ('Threshold must be >= 1');
    if (threshold <= givenShares.length) throw new Error('Number of given shares exceeds threshold')
    const xys = new Array(threshold);
    xys[0] = [__0n, secret];
    let index = 1;
    while (index < threshold) {
      const x = index;
      const y = index <= givenShares.length ? givenShares[index - 1] : await this.ctx.randomScalar();
      xys[index] = [x, y];
      index++;
    }
    const polynomial = await lagrange.interpolate(this.ctx, xys);
    return new ScalarSharing<P>(this.ctx, nrShares, threshold, polynomial);
  }

  verifyFeldmann = async (
    share: ScalarShare<P>,
    commitments: P[],
  ): Promise<boolean> => {
    const { value: secret, index } = share;
    return verifyFeldmann(this.ctx, secret, index, commitments);
  }

   verifyPedersen = async (
    share: ScalarShare<P>,
    binding: bigint,
    pub: P,
    commitments: P[],
  ): Promise<boolean> => {
    const { value: secret, index } = share;
    return verifyPedersen(this.ctx, secret, binding, index, pub, commitments);
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

  reconstructSecret = (qualifiedSet: ScalarShare<P>[]): bigint => {
    const { order } = this.ctx;
    const indexes = qualifiedSet.map(share => share.index);
    return qualifiedSet.reduce((acc, share) => {
      const { value, index } = share;
      const lambda = this.computeLambda(index, indexes);
      return mod(acc + value * lambda, order);
    }, __0n);
  }

  reconstructPublic = async (qualifiedSet: PointShare<P>[]): Promise<P> => {
    const { order, combine, neutral, operate } = this.ctx;
    const indexes = qualifiedSet.map(share => share.index);
    let acc = neutral;
    for (const { index, value } of qualifiedSet) {
      const lambda = this.computeLambda(index, indexes);
      acc = await combine(acc, await operate(lambda, value));
    }
    return acc;
  }
}


export default function<P extends Point>(ctx: Group<P>) {
  return new ShamirDealer(ctx);
}

