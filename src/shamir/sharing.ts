import { Point, Group } from '../backend/abstract';
import { mod } from '../utils';
import { Polynomial, Lagrange, verifyFeldmannCommitments, verifyPedersenCommitments } from '../polynomials';
import { SecretShare, PointShare, Distribution, selectShare, computeLambda } from './common';
import { Messages } from './enums';
import { Share } from '../types';

const polynomials = require('../polynomials');

const __0n = BigInt(0);
const __1n = BigInt(1);


export async function shareSecret<P extends Point>(
  ctx: Group<P>,
  secret: bigint,
  nrShares: number,
  threshold: number,
  givenShares?: bigint[],
): Promise<Distribution<P>> {
  const generatePoints = async (): Promise<[bigint, bigint][]>=> {
    givenShares = givenShares || [];
    const points = new Array(threshold);
    points[0] = [__0n, secret];
    let index = 1;
    while (index < threshold) {
      const x = index;
      const y = index <= givenShares.length ? givenShares[index - 1] : await ctx.randomScalar();
      points[index] = [x, y];
      index++;
    }
    return points;
  }
  givenShares = givenShares || [];
  if (threshold > nrShares) throw new Error(Messages.THRESHOLD_EXCEEDS_NR_SHARES);
  if (threshold < 1) throw new Error (Messages.THRESHOLD_NOT_GE_ONE);
  if (threshold <= givenShares.length) throw new Error(Messages.NR_GIVEN_SHARES_GT_THRESHOLD)
  const polynomial = await Lagrange.interpolate(ctx, await generatePoints());
  return new Distribution<P>(ctx, nrShares, threshold, polynomial);
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
