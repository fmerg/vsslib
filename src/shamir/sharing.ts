import { Point, Group } from '../backend/abstract';
import { mod } from '../utils';
import { Polynomial, Lagrange, verifyFeldmannCommitments, verifyPedersenCommitments } from '../polynomials';
import { Share, selectShare, computeLambda } from './common';
import { Share } from '../types';
import { Messages } from './enums';
import { Share } from '../types';

const polynomials = require('../polynomials');

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


export class PointShare<P extends Point> implements Share<P> {
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
  polynomial: Polynomial<P>;
  commitments: P[];

  constructor(
    ctx: Group<P>,
    threshold: number,
    secretShares: SecretShare<P>[],
    polynomial: Polynomial<P>,
    commitments: P[]
  ) {
    this.ctx = ctx;
    this.threshold = threshold;
    this.secretShares = secretShares;
    this.polynomial = polynomial;
    this.commitments = commitments;
  }

  publicShares = async (): Promise<PointShare<P>[]> => {
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
  polynomial: Polynomial<P>,
  nrShares: number
): Promise<SecretShare<P>[]> {
  const shares = [];
  for (let index = 1; index <= nrShares; index++) {
    const value = polynomial.evaluate(index);
    shares.push({ value, index });
  }
  return shares;
}


export async function shareSecret<P extends Point>(
  ctx: Group<P>,
  secret: bigint,
  nrShares: number,
  threshold: number,
  givenShares?: bigint[],
): Promise<Distribution<P>> {
  const { label, order, randomScalar } = ctx;
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
  const polynomial = await Lagrange.interpolate(ctx, points);
  const secretShares = await computeSecretShares(polynomial, nrShares);
  const { commitments } = await polynomial.generateFeldmannCommitments()
  return new Distribution<P>(ctx, threshold, secretShares, polynomial, commitments);
}


export async function verifySecretShare<P extends Point>(
  ctx: Group<P>,
  share: SecretShare<P>,
  commitments: P[],
): Promise<boolean> {
  const { value: secret, index } = share;
  const isValid = await verifyFeldmannCommitments(ctx, secret, index, commitments);
  if (!isValid) throw new Error(Messages.INVALID_SECRET_SHARE);
  return isValid;
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
