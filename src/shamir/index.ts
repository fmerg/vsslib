import { Algorithm } from '../types';
import { Algorithms } from '../enums';
import { Point, Group } from '../elgamal/abstract';
import { CryptoSystem, Ciphertext } from '../elgamal/core';
import { mod, modInv } from '../utils';
import { Polynomial } from '../lagrange';
import { Messages } from './enums';


const __0n = BigInt(0);
const __1n = BigInt(1);

export type SecretShare = {
  secret: bigint,
  index: number,
};


export type PublicShare = {
  value: Point,
  index: number,
};


export type ShareSetup = {
  nrShares: number,
  threshold: number,
  polynomial: Polynomial
  secret: bigint,
  shares: SecretShare[],
  commitments: Point[],
};


export type DecryptorShare = {
  decryptor: Point,
  index: number,
  proof: any,   // TODO
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
    const secret = poly.evaluate(index);
    shares.push({ secret, index });
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
  const { secret, index: i } = share;
  const target = await ctx.operate(secret, ctx.generator);
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
    const { secret, index } = share;
    const lambda = computeLambda(index, indexes, order);
    return mod(acc + mod(secret * lambda, order), order);
  }, __0n);
}


export const generateDecryptorShare = async (
  ctx: any,
  ciphertext: Ciphertext<Point>,
  share: SecretShare,
  opts?: { algorithm?: Algorithm },
): Promise<DecryptorShare> => {
  const algorithm = extractAlgorithm(opts);
  const { index, secret } = share;
  const decryptor = await ctx.operate(secret, ciphertext.beta);
  const proof = await ctx.proveDecryptor(ciphertext, secret, decryptor, { algorithm });
  return { decryptor, index, proof };
}


export const verifyDecryptorShare = async (
  ctx: any,
  share: DecryptorShare,
  ciphertext: Ciphertext<Point>,
  pub: Point
): Promise<boolean> => {
  const { decryptor, proof } = share;
  const isValid = await ctx.verifyDecryptor(decryptor, ciphertext, pub, proof);
  if (!isValid) throw new Error(Messages.INVALID_DECRYPTOR_SHARE);
  return true;
}


export const selectShare = (index: number, shares: PublicShare[]): PublicShare => {
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
    const lambdai = computeLambda(share.index, qualifiedIndexes, ctx.order);
    const curr = await ctx.operate(lambdai, share.decryptor);
    acc = await ctx.combine(acc, curr);
  }
  return acc;
}
