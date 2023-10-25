import { Key } from '../key';
import { Point, Group } from '../elgamal/abstract';
import { CryptoSystem } from '../elgamal/core';
import { mod } from '../utils';
import { Polynomial } from '../lagrange';
import { Messages } from './enums';

export type KeyShare = {
  key: Key,
  index: number,
};


export type ShareSetup = {
  nrShares: number,
  threshold: number,
  polynomial: Polynomial
  key: Key,
  shares: KeyShare[],
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


export const computeKeyShares = async (ctx: any, poly: Polynomial, nrShares: number): Promise<KeyShare[]> => {
  const shares = [];
  for (let index = 1; index <= nrShares; index++) {
    const key = new Key(ctx, poly.evaluate(index));
    shares.push({ key, index });
  }
  return shares;
}


export const shareSecret = async (ctx: any, nrShares: number, threshold: number): Promise<ShareSetup> => {
  if (threshold > nrShares) throw new Error(Messages.THRESHOLD_EXCEEDS_NR_SHARES);
  const polynomial = await Polynomial.random({ degree: threshold - 1, order: ctx.order });
  const key = new Key(ctx, polynomial.coeffs[0]);
  const shares = await computeKeyShares(ctx, polynomial, nrShares);
  const commitments = await computeCommitments(ctx, polynomial);
  return { nrShares, threshold, polynomial, key, shares, commitments };
}


export const verifyKeyShare = async (ctx: any, share: KeyShare, commitments: Point[]): Promise<boolean> => {
  const { key, index: i } = share;
  const target = await ctx.operate(key.secret, ctx.generator);
  let acc = ctx.neutral;
  for (const [j, comm] of commitments.entries()) {
    const curr = await ctx.operate(mod(BigInt(i ** j), ctx.order), comm);
    acc = await ctx.combine(acc, curr);
  }
  if (!(await acc.isEqual(target))) throw new Error(Messages.INVALID_KEY_SHARE);
  return true;
}
