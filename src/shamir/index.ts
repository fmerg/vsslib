import { Point, Group } from '../backend/abstract';
import { mod, modInv } from '../crypto/arith';
import { BaseShare, BaseSharing } from '../base';
import { ErrorMessages } from '../errors';

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


export function validateThresholdParams<P extends Point>(
  ctx: Group<P>,
  nrShares: number,
  predefined: [bigint, bigint][],
  threshold: number
) {
  if (nrShares < 1) throw new Error(ErrorMessages.NR_SHARES_BELOW_ONE);
  if (threshold < 1) throw new Error(ErrorMessages.THRESHOLD_BELOW_ONE);
  if (threshold > nrShares) throw new Error(ErrorMessages.THRESHOLD_EXCEEDS_NR_SHARES);
  if (!(nrShares < ctx.order)) throw new Error(ErrorMessages.NR_SHARES_VIOLATES_ORDER);
  if (!(predefined.length < threshold)) throw new Error(
    ErrorMessages.NR_PREDEFINED_VIOLATES_THRESHOLD
  );
}


export async function shareSecret<P extends Point>(
  ctx: Group<P>,
  nrShares: number,
  threshold: number,
  secret: bigint,
  predefined?: [bigint, bigint][]
): Promise<SecretSharing<P>> {
  predefined = predefined || [];
  validateThresholdParams(ctx, nrShares, predefined, threshold);
  const xyPoints = new Array(threshold);
  xyPoints[0] = [__0n, secret];
  let index = 1;
  while (index < threshold) {
    const x = index;
    const y = index <= predefined.length ? predefined[index - 1] :
      await ctx.randomScalar();
    xyPoints[index] = [x, y];
    index++;
  }
  const polynomial = await lagrange.interpolate(ctx, xyPoints);
  return new SecretSharing<P>(ctx, nrShares, threshold, polynomial);
}


export async function verifyFeldmann<P extends Point>(
  ctx: Group<P>,
  share: SecretShare<P>,
  commitments: P[]
): Promise<boolean> {
  const { value: secret, index } = share;
  const { order, generator, neutral, operate, combine } = ctx;
  const lhs = await operate(secret, generator);
  let rhs = neutral;
  const i = index;
  for (const [j, c] of commitments.entries()) {
    const curr = await operate(mod(BigInt(i ** j), order), c);
    rhs = await combine(rhs, curr);
  }
  return lhs.equals(rhs);
}


export async function verifyPedersen<P extends Point>(
  ctx: Group<P>,
  share: SecretShare<P>,
  binding: bigint,
  pub: P,
  commitments: P[],
): Promise<boolean> {
  const { value: secret, index } = share;
  const { order, generator: g, neutral, operate, combine } = ctx;
  const lhs = await combine(await operate(secret, g), await operate(binding, pub));
  let rhs = neutral;
  const i = index;
  for (const [j, c] of commitments.entries()) {
    rhs = await combine(rhs, await operate(BigInt(i ** j), c));
  }
  return lhs.equals(rhs);
}


export function computeLambda<P extends Point>(
  ctx: Group<P>,
  index: number,
  qualifiedIndexes: number[]
): bigint {
  let lambda = __1n;
  const { order } = ctx
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
  qualifiedShares: SecretShare<P>[]
): bigint {
  const { order } = ctx;
  const indexes = qualifiedShares.map(share => share.index);
  return qualifiedShares.reduce(
    (acc, { value, index }) => {
      const lambda = computeLambda(ctx, index, indexes);
      return mod(acc + value * lambda, order);
    },
    __0n
  );
}


export async function reconstructPublic<P extends Point>(
  ctx: Group<P>,
  qualifiedShares: PubShare<P>[]
): Promise<P> {
  const { order, combine, neutral, operate } = ctx;
  const indexes = qualifiedShares.map(share => share.index);
  let acc = neutral;
  for (const { index, value } of qualifiedShares) {
    const lambda = computeLambda(ctx, index, indexes);
    acc = await combine(acc, await operate(lambda, value));
  }
  return acc;
}
