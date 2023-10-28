import { Algorithm } from '../types';
import { Algorithms } from '../enums';
import { Point, Group } from '../elgamal/abstract';
import { CryptoSystem, Ciphertext, DlogProof } from '../elgamal/core';
import { mod, modInv } from '../utils';
import { Polynomial } from '../lagrange';
import { Messages } from './enums';

const lagrange = require('../lagrange');

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


export class Distribution<P extends Point> {
  ctx: CryptoSystem<P, Group<P>>;
  threshold: number;
  shares: SecretShare<P>[];
  polynomial: Polynomial;
  commitments: P[];

  constructor(
    ctx: CryptoSystem<P, Group<P>>,
    threshold: number,
    shares: SecretShare<P>[],
    polynomial: Polynomial,
    commitments: P[]
  ) {
    this.ctx = ctx;
    this.threshold = threshold;
    this.shares = shares;
    this.polynomial = polynomial;
    this.commitments = commitments;
  }

  getPublicShares = async (): Promise<PublicShare<P>[]> => {
    const { operate, generator } = this.ctx;
    const shares = [];
    for (const share of this.shares) {
      const { value: secret, index } = share;
      const value = await operate(secret, generator);
      shares.push({ value, index });
    }
    return shares;
  }
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
  if (!selected) throw new Error(Messages.NO_SHARE_WITH_INDEX);
  return selected;
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


export async function computeCommitments<P extends Point>(
  ctx: CryptoSystem<P, Group<P>>,
  polynomial: Polynomial
): Promise<P[]> {
  const { operate, generator } = ctx;
  const commitments = new Array(polynomial.degree + 1);
  for (const [index, coeff] of polynomial.coeffs.entries()) {
    commitments[index] = await operate(coeff, generator);
  }
  return commitments;
}


export async function shareSecret<P extends Point>(
  ctx: CryptoSystem<P, Group<P>>,
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
  const degree = threshold - 1;
  const points = new Array(degree + 1);
  points[0] = [0, secret];
  let index = 1;
  while (index < points.length) {
    const x = index;
    const y = index <= givenShares.length ? givenShares[index - 1] : await randomScalar();
    points[index] = [x, y];
    index++;
  }
  const polynomial = lagrange.interpolate(points, { order });
  const shares = await computeSecretShares(polynomial, nrShares);
  const commitments = await computeCommitments(ctx, polynomial);
  return new Distribution<P>(ctx, threshold, shares, polynomial, commitments);
}


export async function verifySecretShare<P extends Point>(
  ctx: CryptoSystem<P, Group<P>>,
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
  ctx: CryptoSystem<P, Group<P>>,
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


export async function generateDecryptorShare<P extends Point>(
  ctx: CryptoSystem<P, Group<P>>,
  ciphertext: Ciphertext<P>,
  share: SecretShare<P>,
  opts?: { algorithm?: Algorithm },
): Promise<DecryptorShare<P>> {
  const { operate, proveDecryptor } = ctx;
  const algorithm = extractAlgorithm(opts);
  const { value, index } = share;
  const decryptor = await operate(value, ciphertext.beta);
  const proof = await proveDecryptor(ciphertext, value, decryptor, { algorithm });
  return { value: decryptor, index, proof}
}


export async function verifyDecryptorShare<P extends Point>(
  ctx: CryptoSystem<P, Group<P>>,
  share: DecryptorShare<P>,
  ciphertext: Ciphertext<P>,
  publicShare: PublicShare<P>,
): Promise<boolean> {
  const { value: pub } = publicShare;
  const { value, proof } = share;
  const verified = await ctx.verifyDecryptor(value, ciphertext, pub, proof);
  if (!verified) throw new Error(Messages.INVALID_DECRYPTOR_SHARE);
  return true;
}


export async function verifyDecryptorShares<P extends Point>(
  ctx: CryptoSystem<P, Group<P>>,
  shares: DecryptorShare<P>[],
  ciphertext: Ciphertext<P>,
  publicShares: PublicShare<P>[],
): Promise<[boolean, number[]]> {
  let flag = true;
  let indexes = [];
  for (const share of shares) {
    const { value, index, proof } = share;
    const { value: pub } = selectShare(index, publicShares);
    const verified = await ctx.verifyDecryptor(value, ciphertext, pub, proof);
    flag &&= verified;
    if (!verified) indexes.push(index);
  }
  return [flag, indexes];
}


export async function reconstructDecryptor<P extends Point>(
  ctx: CryptoSystem<P, Group<P>>,
  shares: DecryptorShare<P>[],
): Promise<P> {
  const { order, neutral, operate, combine } = ctx;
  const qualifiedIndexes = shares.map(share => share.index);
  let acc = neutral;
  for (const share of shares) {
    const { value, index } = share;
    const lambda = computeLambda(index, qualifiedIndexes, order);
    const curr = await operate(lambda, value);
    acc = await combine(acc, curr);
  }
  return acc;
}


export async function decrypt<P extends Point>(
  ctx: CryptoSystem<P, Group<P>>,
  ciphertext: Ciphertext<P>,
  shares: DecryptorShare<P>[],
  opts?: { threshold?: number, publicShares?: PublicShare<P>[] },
): Promise<P> {
  const threshold = opts ? opts.threshold : undefined;
  const publicShares = opts ? opts.publicShares : undefined;
  if (threshold && shares.length < threshold) throw new Error(Messages.NOT_ENOUGH_SHARES);
  if (publicShares) {
    const [verified, indexes] = await verifyDecryptorShares(
      ctx, shares, ciphertext, publicShares
    );
    if (!verified) throw new Error(Messages.INVALID_DECRYPTOR_SHARES_DETECTED);
  }
  const decryptor = await reconstructDecryptor(ctx, shares);
  return ctx.decrypt(ciphertext, { decryptor });
}
