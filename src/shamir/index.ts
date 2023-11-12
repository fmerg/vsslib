import { Point, Group } from '../backend/abstract';
import { Polynomial, Lagrange, verifyFeldmannCommitments, verifyPedersenCommitments } from '../polynomials';
import { Algorithm, BaseShare, BaseDistribution } from '../common';
import { Algorithms } from '../enums';
import { mod, modInv } from '../utils';

const polynomials = require('../polynomials');

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


export class ScalarDistribution<P extends Point> extends BaseDistribution<
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


export async function shareSecret<P extends Point>(
  ctx: Group<P>,
  secret: bigint,
  nrShares: number,
  threshold: number,
  givenShares?: bigint[],
): Promise<ScalarDistribution<P>> {
  givenShares = givenShares || [];
  if (threshold > nrShares) throw new Error('Threshold exceeds number of shares');
  if (threshold < 1) throw new Error ('Threshold must be >= 1');
  if (threshold <= givenShares.length) throw new Error('Number of given shares exceeds threshold')
  const xys = new Array(threshold);
  xys[0] = [__0n, secret];
  let index = 1;
  while (index < threshold) {
    const x = index;
    const y = index <= givenShares.length ? givenShares[index - 1] : await ctx.randomScalar();
    xys[index] = [x, y];
    index++;
  }
  const polynomial = await Lagrange.interpolate(ctx, xys);
  return new ScalarDistribution<P>(ctx, nrShares, threshold, polynomial);
}


export async function verifySecretShare<P extends Point>(
  ctx: Group<P>,
  share: ScalarShare<P>,
  commitments: P[],
  extras?: { binding: bigint, hPub: P },
): Promise<boolean> {
  const { value: secret, index } = share;
  if (extras) {
    const { binding, hPub } = extras;
    return verifyPedersenCommitments(ctx, secret, binding, index, hPub, commitments);
  }
  return verifyFeldmannCommitments(ctx, secret, index, commitments);
}


export function computeLambda(index: number, qualifiedIndexes: number[], order: bigint): bigint {
  let lambda = __1n;
  const i = index;
  qualifiedIndexes.forEach(j => {
    if (i != j) {
      const curr = BigInt(j) * modInv(BigInt(j - i), order);
      lambda = mod(lambda * curr, order);
    }
  });
  return lambda;
}


export function reconstructSecret<P extends Point>(
  ctx: Group<P>,
  qualifiedSet: ScalarShare<P>[],
): bigint {
  const { order } = ctx;
  const indexes = qualifiedSet.map(share => share.index);
  return qualifiedSet.reduce((acc, share) => {
    const { value, index } = share;
    const lambda = computeLambda(index, indexes, order);
    return mod(acc + value * lambda, order);
  }, __0n);
}


export async function reconstructPublic<P extends Point>(
  ctx: Group<P>,
  qualifiedSet: PointShare<P>[],
): Promise<P> {
  const { order, combine, neutral } = ctx;
  const indexes = qualifiedSet.map(share => share.index);
  let acc = neutral;
  for (const { index, value } of qualifiedSet) {
    const lambda = computeLambda(index, indexes, order);
    acc = await combine(acc, await ctx.operate(lambda, value));
  }
  return acc;
}
