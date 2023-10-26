import { Algorithm } from '../types';
import { Algorithms } from '../enums';
import { Point, Group } from '../elgamal/abstract';
import { CryptoSystem, Ciphertext } from '../elgamal/core';
import { mod, modInv } from '../utils';
import { Polynomial } from '../lagrange';
import { Messages } from './enums';


const __0n = BigInt(0);
const __1n = BigInt(1);


export abstract class Share<T> {
  value: T;
  index: number;

  constructor(value: T, index: number) {
    this.value = value;
    this.index = index;
  }
}


export class SecretShare implements Share<bigint> {
  value: bigint;
  index: number;

  constructor(value: bigint, index: number) {
    this.value = value;
    this.index = index;
  }
};


export class PublicShare implements Share<Point> {
  value: Point;
  index: number;

  constructor(value: Point, index: number) {
    this.value = value;
    this.index = index;
  }
};


export class DecryptorShare implements Share<Point> {
  value: Point;
  index: number;
  proof: any;   // TODO

  constructor(value: Point, index: number, proof: any) {
    this.value = value;
    this.index = index;
    this.proof = proof;
  }
};


export type ShareSetup = {
  nrShares: number,
  threshold: number,
  polynomial: Polynomial
  secret: bigint,
  shares: SecretShare[],
  commitments: Point[],
};


const extractAlgorithm = (opts: any): Algorithm => opts ?
  (opts.algorithm || Algorithms.DEFAULT) :
  Algorithms.DEFAULT;


export const computeCommitments = async (ctx: any, poly: Polynomial): Promise<Point[]> => {
  const commitments = new Array(poly.degree + 1);
  for (const [index, coeff] of poly.coeffs.entries()) {
    commitments[index] = await ctx.operate(coeff, ctx.generator);
  }
  return commitments;
}


export const computeSecretShares = async (ctx: any, poly: Polynomial, nrShares: number): Promise<SecretShare[]> => {
  const shares = [];
  for (let index = 1; index <= nrShares; index++) {
    const value = poly.evaluate(index);
    shares.push({ value, index });
  }
  return shares;
}


export const shareSecret = async (ctx: any, nrShares: number, threshold: number): Promise<ShareSetup> => {
  if (threshold > nrShares) throw new Error(Messages.THRESHOLD_EXCEEDS_NR_SHARES);
  const polynomial = await Polynomial.random({ degree: threshold - 1, order: ctx.order });
  const secret = polynomial.coeffs[0];
  const shares = await computeSecretShares(ctx, polynomial, nrShares);
  const commitments = await computeCommitments(ctx, polynomial);
  return { nrShares, threshold, polynomial, secret, shares, commitments };
}


export const verifySecretShare = async (ctx: any, share: SecretShare, commitments: Point[]): Promise<boolean> => {
  const target = await ctx.operate(share.value, ctx.generator);
  const i = share.index;
  let acc = ctx.neutral;
  for (const [j, comm] of commitments.entries()) {
    const curr = await ctx.operate(mod(BigInt(i ** j), ctx.order), comm);
    acc = await ctx.combine(acc, curr);
  }
  if (!(await acc.isEqual(target))) throw new Error(Messages.INVALID_SECRET_SHARE);
  return true;
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


export const reconstructSecret = (qualifiedSet: SecretShare[], order: bigint): bigint => {
  const indexes = qualifiedSet.map(share => share.index);
  return qualifiedSet.reduce((acc, share) => {
    const { value, index } = share;
    const lambda = computeLambda(index, indexes, order);
    return mod(acc + mod(value * lambda, order), order);
  }, __0n);
}


export const generateDecryptorShare = async (
  ctx: any,
  ciphertext: Ciphertext<Point>,
  share: SecretShare,
  opts?: { algorithm?: Algorithm },
): Promise<DecryptorShare> => {
  const algorithm = extractAlgorithm(opts);
  const { value, index } = share;
  const decryptor = await ctx.operate(value, ciphertext.beta);
  const proof = await ctx.proveDecryptor(ciphertext, value, decryptor, { algorithm });
  return { value: decryptor, index, proof}
}


export const verifyDecryptorShare = async (
  ctx: any,
  share: DecryptorShare,
  ciphertext: Ciphertext<Point>,
  pub: Point
): Promise<boolean> => {
  const { value, proof } = share;
  const isValid = await ctx.verifyDecryptor(value, ciphertext, pub, proof);
  if (!isValid) throw new Error(Messages.INVALID_DECRYPTOR_SHARE);
  return true;
}


export function selectShare<T>(index: number, shares: Share<T>[]): Share<T> {
  const selected = shares.filter(share => share.index == index)[0];
  if (!selected) throw new Error(Messages.NO_SHARE_FOUND_FOR_INDEX);
  return selected;
}


export const verifyDecryptorShares = async (
  ctx: any,
  shares: DecryptorShare[],
  ciphertext: Ciphertext<Point>,
  publicShares: PublicShare[],
): Promise<boolean> => {
  // TODO: Make it constant time
  // TODO: Refine error handling
  for (const share of shares) {
    const pub = selectShare(share.index, publicShares).value;
    verifyDecryptorShare(ctx, share, ciphertext, pub);
  }
  return true
}

export const reconstructDecryptor = async (ctx: any, shares: DecryptorShare[]): Promise<Point> => {
  const qualifiedIndexes = shares.map(share => share.index);
  let acc = ctx.neutral;
  for (const share of shares) {
    const lambda = computeLambda(share.index, qualifiedIndexes, ctx.order);
    const curr = await ctx.operate(lambda, share.value);
    acc = await ctx.combine(acc, curr);
  }
  return acc;
}
