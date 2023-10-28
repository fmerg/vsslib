import { Point, Group } from '../elgamal/abstract';
import { CryptoSystem } from '../elgamal/core';
import { mod } from '../utils';
import { Polynomial } from '../lagrange';
import { Share, selectShare, computeLambda } from './common';
import { Messages } from './enums';

const lagrange = require('../lagrange');

const __0n = BigInt(0);
const __1n = BigInt(1);


export class SecretShare<P extends Point> implements Share<bigint> {
  value: bigint;
  index: number;

  constructor(value: bigint, index: number) {
    this.value = value;
    this.index = index;
  }
};


export class PublicShare<P extends Point> implements Share<P> {
  value: P;
  index: number;

  constructor(value: P, index: number) {
    this.value = value;
    this.index = index;
  }
};


export class Distribution<P extends Point> {
  ctx: CryptoSystem<P>;
  threshold: number;
  shares: SecretShare<P>[];
  polynomial: Polynomial;
  commitments: P[];

  constructor(
    ctx: CryptoSystem<P>,
    threshold: number,
    shares: SecretShare<P>[],
    polynomial: Polynomial,
    commitments: P[]
  ) {
    this.ctx = ctx;
    this.threshold = threshold;
    this.shares = shares;
    this.polynomial = polynomial;
    this.commitments = commitments;
  }

  getPublicShares = async (): Promise<PublicShare<P>[]> => {
    const { operate, generator } = this.ctx;
    const shares = [];
    for (const share of this.shares) {
      const { value: secret, index } = share;
      const value = await operate(secret, generator);
      shares.push({ value, index });
    }
    return shares;
  }
};


export async function computeSecretShares<P extends Point>(
  polynomial: Polynomial,
  nrShares: number
): Promise<SecretShare<P>[]> {
  const shares = [];
  for (let index = 1; index <= nrShares; index++) {
    const value = polynomial.evaluate(index);
    shares.push({ value, index });
  }
  return shares;
}


export async function computeCommitments<P extends Point>(
  ctx: CryptoSystem<P>,
  polynomial: Polynomial
): Promise<P[]> {
  const { operate, generator } = ctx;
  const commitments = new Array(polynomial.degree + 1);
  for (const [index, coeff] of polynomial.coeffs.entries()) {
    commitments[index] = await operate(coeff, generator);
  }
  return commitments;
}


export async function shareSecret<P extends Point>(
  ctx: CryptoSystem<P>,
  secret: bigint,
  nrShares: number,
  threshold: number,
  givenShares?: bigint[],
): Promise<Distribution<P>> {
  const { order, randomScalar } = ctx;
  givenShares = givenShares || [];
  if (threshold > nrShares) throw new Error(Messages.THRESHOLD_EXCEEDS_NR_SHARES);
  if (threshold < 1) throw new Error (Messages.THRESHOLD_NOT_GE_ONE);
  if (threshold <= givenShares.length) throw new Error(Messages.NR_GIVEN_SHARES_GT_THRESHOLD)
  const degree = threshold - 1;
  const points = new Array(degree + 1);
  points[0] = [0, secret];
  let index = 1;
  while (index < points.length) {
    const x = index;
    const y = index <= givenShares.length ? givenShares[index - 1] : await randomScalar();
    points[index] = [x, y];
    index++;
  }
  const polynomial = lagrange.interpolate(points, { order });
  const shares = await computeSecretShares(polynomial, nrShares);
  const commitments = await computeCommitments(ctx, polynomial);
  return new Distribution<P>(ctx, threshold, shares, polynomial, commitments);
}


export async function verifySecretShare<P extends Point>(
  ctx: CryptoSystem<P>,
  share: SecretShare<P>,
  commitments: P[],
): Promise<boolean> {
  const { order, generator, neutral, operate, combine } = ctx;
  const target = await operate(share.value, generator);
  const { index: i } = share;
  let acc = neutral;
  for (const [j, comm] of commitments.entries()) {
    const curr = await operate(mod(BigInt(i ** j), order), comm);
    acc = await combine(acc, curr);
  }
  if (!(await acc.isEqual(target))) throw new Error(Messages.INVALID_SECRET_SHARE);
  return true;
}


export function reconstructSecret<P extends Point>(
  ctx: CryptoSystem<P>,
  qualifiedSet: SecretShare<P>[],
): bigint {
  const { order } = ctx;
  const indexes = qualifiedSet.map(share => share.index);
  return qualifiedSet.reduce((acc, share) => {
    const { value, index } = share;
    const lambda = computeLambda(index, indexes, order);
    return mod(acc + value * lambda, order);
  }, __0n);
}
