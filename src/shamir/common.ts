import { Point, Group } from '../backend/abstract';
import { Algorithm } from '../types';
import { Algorithms } from '../enums';
import { mod, modInv } from '../utils';
import { Messages } from './enums';
import { Polynomial } from '../polynomials';
import { Share } from '../types';


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
  nrShares: number;
  threshold: number;
  polynomial: Polynomial<P>;

  constructor(ctx: Group<P>, nrShares: number, threshold: number, polynomial: Polynomial<P>) {
    this.ctx = ctx;
    this.threshold = threshold;
    this.nrShares = nrShares;
    this.polynomial = polynomial;
  }

  getSecretShares = async (): Promise<SecretShare<P>[]> => {
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

  getFeldmannCommitments = async (): Promise<{ commitments: P[] }> => {
    return this.polynomial.generateFeldmannCommitments();
  }

  getPedersenCommitments = async (hPub?: P): Promise<{
    bindings: bigint[],
    hPub: P,
    commitments: P[],
  }> => {
    const { ctx, nrShares, polynomial } = this;
    return polynomial.generatePedersenCommitments(nrShares, hPub || await ctx.randomPoint());
  }
};


export function selectShare<T>(index: number, shares: Share<T>[]): Share<T> {
  const selected = shares.filter(share => share.index == index)[0];
  if (!selected) throw new Error(Messages.NO_SHARE_WITH_INDEX);
  return selected;
}


export const computeLambda = (index: number, qualifiedIndexes: number[], order: bigint): bigint => {
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
