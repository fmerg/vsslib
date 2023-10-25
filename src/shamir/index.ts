import { Point, Group } from '../elgamal/abstract';
import { CryptoSystem } from '../elgamal/core';
import { mod } from '../utils';
import { Polynomial } from '../lagrange';
import { Messages } from './enums';

export type SecretShare = {
  secret: bigint,
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
