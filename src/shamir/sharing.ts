import { Point, Group } from '../backend/abstract';
import { mod } from '../utils';
import { BasePolynomial } from '../lagrange';
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
  ctx: Group<P>;
  threshold: number;
  secretShares: SecretShare<P>[];
  polynomial: BasePolynomial;
  commitments: P[];

  constructor(
    ctx: Group<P>,
    threshold: number,
    secretShares: SecretShare<P>[],
    polynomial: BasePolynomial,
    commitments: P[]
  ) {
    this.ctx = ctx;
    this.threshold = threshold;
    this.secretShares = secretShares;
    this.polynomial = polynomial;
    this.commitments = commitments;
  }

  publicShares = async (): Promise<PublicShare<P>[]> => {
    const { operate, generator } = this.ctx;
    const shares = [];
    for (const { value: secret, index } of this.secretShares) {
      const value = await operate(secret, generator);
      shares.push({ value, index });
    }
    return shares;
  }
};


export async function computeSecretShares<P extends Point>(
  polynomial: BasePolynomial,
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
  ctx: Group<P>,
  polynomial: BasePolynomial
): Promise<P[]> {
  const { operate, generator } = ctx;
  const commitments = new Array(polynomial.degree + 1);
  for (const [index, coeff] of polynomial.coeffs.entries()) {
    commitments[index] = await operate(coeff, generator);
  }
  return commitments;
}


export async function shareSecret<P extends Point>(
  ctx: Group<P>,
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
  const points = new Array(threshold);
  points[0] = [0, secret];
  let index = 1;
  while (index < points.length) {
    const x = index;
    const y = index <= givenShares.length ? givenShares[index - 1] : await randomScalar();
    points[index] = [x, y];
    index++;
  }
  const polynomial = lagrange.interpolate(points, { order });
  const secretShares = await computeSecretShares(polynomial, nrShares);
  const commitments = await computeCommitments(ctx, polynomial);
  return new Distribution<P>(ctx, threshold, secretShares, polynomial, commitments);
}


export async function verifySecretShare<P extends Point>(
  ctx: Group<P>,
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
  ctx: Group<P>,
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


export async function reconstructPublic<P extends Point>(
  ctx: Group<P>,
  qualifiedSet: PublicShare<P>[],
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
