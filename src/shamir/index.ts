import { Algorithm } from '../types';
import { Algorithms } from '../enums';
import { Point, Group } from '../elgamal/abstract';
import { CryptoSystem, Ciphertext, DlogProof } from '../elgamal/core';
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


export class DecryptorShare<P extends Point> implements Share<P> {
  value: P;
  index: number;
  proof: DlogProof<P>;

  constructor(value: P, index: number, proof: DlogProof<P>) {
    this.value = value;
    this.index = index;
    this.proof = proof;
  }
};


export type ShareSetup<P extends Point> = {
  nrShares: number,
  threshold: number,
  polynomial: Polynomial
  secret: bigint,
  shares: SecretShare<P>[],
  commitments: P[],
};


const extractAlgorithm = (opts: any): Algorithm => opts ?
  (opts.algorithm || Algorithms.DEFAULT) :
  Algorithms.DEFAULT;


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


export function selectShare<T>(index: number, shares: Share<T>[]): Share<T> {
  const selected = shares.filter(share => share.index == index)[0];
  if (!selected) throw new Error(Messages.NO_SHARE_FOUND_FOR_INDEX);
  return selected;
}


export async function computeCommitments<P extends Point>(
  ctx: CryptoSystem<P, Group<P>>,
  polynomial: Polynomial
): Promise<P[]> {
  const commitments = new Array(polynomial.degree + 1);
  for (const [index, coeff] of polynomial.coeffs.entries()) {
    commitments[index] = await ctx.operate(coeff, ctx.generator);
  }
  return commitments;
}


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


export async function shareSecret<P extends Point>(
  ctx: CryptoSystem<P, Group<P>>,
  nrShares: number,
  threshold: number
): Promise<ShareSetup<P>> {
  if (threshold > nrShares) throw new Error(Messages.THRESHOLD_EXCEEDS_NR_SHARES);
  const polynomial = await Polynomial.random({ degree: threshold - 1, order: ctx.order });
  const secret = polynomial.coeffs[0];
  const shares = await computeSecretShares(polynomial, nrShares);
  const commitments = await computeCommitments(ctx, polynomial);
  return { nrShares, threshold, polynomial, secret, shares, commitments };
}


export async function verifySecretShare<P extends Point>(
  ctx: CryptoSystem<P, Group<P>>,
  share: SecretShare<P>,
  commitments: P[],
): Promise<boolean> {
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


export function reconstructSecret<P extends Point>(
  qualifiedSet: SecretShare<P>[],
  order: bigint
): bigint {
  const indexes = qualifiedSet.map(share => share.index);
  return qualifiedSet.reduce((acc, share) => {
    const { value, index } = share;
    const lambda = computeLambda(index, indexes, order);
    return mod(acc + mod(value * lambda, order), order);
  }, __0n);
}


export async function generateDecryptorShare<P extends Point>(
  ctx: CryptoSystem<P, Group<P>>,
  ciphertext: Ciphertext<P>,
  share: SecretShare<P>,
  opts?: { algorithm?: Algorithm },
): Promise<DecryptorShare<P>> {
  const algorithm = extractAlgorithm(opts);
  const { value, index } = share;
  const decryptor = await ctx.operate(value, ciphertext.beta);
  const proof = await ctx.proveDecryptor(ciphertext, value, decryptor, { algorithm });
  return { value: decryptor, index, proof}
}


export async function verifyDecryptorShare<P extends Point>(
  ctx: CryptoSystem<P, Group<P>>,
  share: DecryptorShare<P>,
  ciphertext: Ciphertext<P>,
  pub: P,
): Promise<boolean> {
  const { value, proof } = share;
  const isValid = await ctx.verifyDecryptor(value, ciphertext, pub, proof);
  if (!isValid) throw new Error(Messages.INVALID_DECRYPTOR_SHARE);
  return true;
}


export async function verifyDecryptorShares<P extends Point>(
  ctx: CryptoSystem<P, Group<P>>,
  shares: DecryptorShare<P>[],
  ciphertext: Ciphertext<P>,
  publicShares: PublicShare<P>[],
): Promise<boolean> {
  // TODO: Make it constant time
  // TODO: Refine error handling
  for (const share of shares) {
    const pub = selectShare(share.index, publicShares).value;
    const { value, proof } = share;
    const isValid = await ctx.verifyDecryptor(value, ciphertext, pub, proof);
    if (!isValid) throw new Error(Messages.INVALID_DECRYPTOR_SHARE);
  }
  return true
}

export async function reconstructDecryptor<P extends Point>(
  ctx: CryptoSystem<P, Group<P>>,
  shares: DecryptorShare<P>[],
): Promise<P> {
  const qualifiedIndexes = shares.map(share => share.index);
  let acc = ctx.neutral;
  for (const share of shares) {
    const lambda = computeLambda(share.index, qualifiedIndexes, ctx.order);
    const curr = await ctx.operate(lambda, share.value);
    acc = await ctx.combine(acc, curr);
  }
  return acc;
}
